//! The Authenticator's side of the WIP-202 Proof of Embedding Similarity: from the request it
//! sends the Flamingo Verifier to the [`ProofResponse`] for the RP.

use alloy::primitives::Bytes;
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::rngs::OsRng;
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};
use world_id_flamingo::{
    FlamingoAatClaims, FlamingoClaims, FlamingoToken, MAX_COMMITTED, MAX_REQUEST_LIFETIME, Payload,
    ReleaseManifest, Request, RequestError, release_manifest::Pipeline,
};
use world_id_primitives::{
    Credential, EmbeddingSimilarityParams, EmbeddingSimilarityResponseItem, FieldElement,
    PrimitiveError, ProofRequest, ProofResponse, ProofType, SessionRef, TREE_DEPTH,
    authenticator_assertion::AatPublicValues, billing::BillingWitness,
};
use world_id_proof::{
    ProofError,
    circuit_inputs::{EmbeddingSimilarityCircuitInput, EmbeddingSimilarityRequestInputs},
    embedding_similarity_proof::{
        PIPELINE_TYPE, authorization_message, flamingo_nonce, generate_embedding_similarity_proof,
    },
};

use crate::{
    api_types::AccountInclusionProof,
    authenticator::{Authenticator, CredentialInput, ProofResult},
    error::AuthenticatorError,
};

/// What the Flamingo Verifier returned for a Proof of Embedding Similarity request (WIP-201
/// §4.5.1), after the Authenticator checked its attestation (WIP-201 §4.7).
#[derive(Debug, Clone)]
pub struct FlamingoResult {
    /// The Flamingo Token the Verifier signed.
    pub token: FlamingoToken,
    /// The Verifier's signing key, as `signing_key_attestation` attests it.
    pub verifier_key: EdDSAPublicKey,
    /// The attestation of `verifier_key`, forwarded to the RP (WIP-201 §4.8 check 1).
    pub signing_key_attestation: Bytes,
    /// The salt the request's `nonce` was derived with, from [`FlamingoAttempt::nonce_salt`].
    pub nonce_salt: FieldElement,
    /// The request's committed entry hashes, from [`FlamingoAttempt::entry_hashes`].
    pub entry_hashes: [FieldElement; MAX_COMMITTED],
    /// The request's strictness, from [`FlamingoAttempt::strictness`].
    pub strictness: u8,
}

/// The images a Proof of Embedding Similarity compares, in the order of the WIP-202 entry layout
/// (§4.4.1).
#[derive(Clone)]
pub struct EmbeddingSimilarityImages {
    /// The PCP thumbnail that the Credential's `hashes.json` lists.
    pub credential_image: Vec<u8>,
    /// The live captures, one per `live` or `evidence` input of the pipeline, in the order of
    /// its `inputs`. The `live` one is committed and matched; `evidence` ones are only checked,
    /// e.g. the unlit frame of a `LightGuard` capture.
    pub live_captures: Vec<LiveCapture>,
    /// The RP's challenge image, whose `R(SHA-256)` is the request's `challenge_hash`, or `None`
    /// for a request without a challenge.
    pub challenge: Option<Vec<u8>>,
}

/// Omits the images, which are biometric data.
impl std::fmt::Debug for EmbeddingSimilarityImages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingSimilarityImages")
            .finish_non_exhaustive()
    }
}

/// One live capture, the entry of one pipeline input.
#[derive(Clone)]
pub struct LiveCapture {
    /// The WIP-202 role of the pipeline input it is: [`LIVE`] or [`EVIDENCE`].
    pub role: String,
    /// The pipeline input's Engine `label`, e.g. `unlit_frame`.
    pub label: String,
    /// The encoded image.
    pub data: Vec<u8>,
}

/// Omits the image, which is biometric data.
impl std::fmt::Debug for LiveCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveCapture")
            .field("role", &self.role)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// The role of the PCP thumbnail in [`PIPELINE_TYPE`].
const CREDENTIAL: &str = "credential";
/// The role of the RP's challenge image in [`PIPELINE_TYPE`].
const CHALLENGE: &str = "challenge";
/// The role of the matched live capture in [`PIPELINE_TYPE`].
pub const LIVE: &str = "live";
/// The role of a live capture the pipeline only checks, in [`PIPELINE_TYPE`].
pub const EVIDENCE: &str = "evidence";

/// Most response release times a chosen pipeline may list, so a response's timing reveals at most
/// 3 bits (WIP-201 §4.7).
const MAX_RESPONSE_SLOTS: usize = 8;

/// How long after the device's `now` a request may expire. The Verifier rejects one expiring more
/// than `MAX_REQUEST_LIFETIME` after its own clock, so the other half absorbs a device clock that
/// runs ahead of it.
const REQUEST_LIFETIME: u64 = MAX_REQUEST_LIFETIME / 2;

/// Builds a Flamingo request (WIP-201 §4.5.1) for a Proof of Embedding Similarity request, with a
/// `nonce` derived from a fresh salt.
///
/// Each call samples a new `nonce_salt` with a CSPRNG and sets the request's `nonce` to
/// [`flamingo_nonce`]`(proof_request.nonce, nonce_salt)` (WIP-202 constraint 1.1), so a retry after
/// a failed capture or a billing rejection is a new request within the same RP request (WIP-201
/// §4.7). Keep the returned salt for the [`FlamingoResult`].
///
/// The pipeline is the first in `release` of [`PIPELINE_TYPE`] that lists `strictness` and whose
/// `live` and `evidence` inputs have the roles and labels of `images.live_captures`, in order, so
/// only the release, not the Verifier, picks it. The result carries no
/// `aat_inputs`: an AAT signs the request's [`Request::cdh`], so the caller obtains one for this
/// request and sets it afterwards.
///
/// # Arguments
/// - `proof_request`: the RP's [`ProofType::EmbeddingSimilarity`] request.
/// - `release`: the release manifest the Verifier's attestation binds (WIP-201 §4.7). The
///   attestation binds the manifest but does not vouch for it, so it MUST also verify under a
///   release key of an Engine Provider the caller trusts (§4.4.3).
/// - `strictness`: the Authenticator Provider's level; WIP-202 requests set none.
/// - `images`: the entries to compare; the challenge must be present exactly when the request
///   has a `challenge_hash`, and hash to it.
/// - `billing_nullifier`: the WIP-107 `billingNullifier` registered for the RP, or `0`.
/// - `now`: the device's time, in Unix seconds. `expires_at` is the request's expiry capped at
///   `now + MAX_REQUEST_LIFETIME / 2`, so a device clock up to `MAX_REQUEST_LIFETIME / 2` ahead of
///   the Verifier's does not get the request rejected.
///
/// # Errors
/// - [`AuthenticatorError::PrimitiveError`] if the request is not a valid Proof of Embedding
///   Similarity request, or the challenge does not match its `challenge_hash`.
/// - [`AuthenticatorError::NoFlamingoPipeline`] if `release` has no pipeline for the captures.
/// - [`AuthenticatorError::StrictnessNotOffered`] if none of those lists `strictness`.
/// - [`AuthenticatorError::FlamingoRequest`] if the request has expired at `now`, or an entry is
///   out of bounds.
pub fn flamingo_request(
    proof_request: &ProofRequest,
    release: &ReleaseManifest,
    strictness: u8,
    images: EmbeddingSimilarityImages,
    billing_nullifier: FieldElement,
    now: u64,
) -> Result<FlamingoAttempt, AuthenticatorError> {
    let nonce_salt = FieldElement::random(&mut OsRng);
    let request = flamingo_request_with_salt(
        proof_request,
        release,
        strictness,
        images,
        billing_nullifier,
        nonce_salt,
        now,
    )?;
    let payload = request.payload()?;
    Ok(FlamingoAttempt {
        entry_hashes: payload.fit(release)?.entry_hashes,
        strictness: payload.strictness,
        request,
        nonce_salt,
    })
}

/// A Flamingo request and the salt its `nonce` was derived with.
#[derive(Clone)]
pub struct FlamingoAttempt {
    /// The request to seal to the Flamingo Verifier.
    pub request: Request,
    /// The salt of the request's `nonce`, for [`FlamingoResult::nonce_salt`].
    pub nonce_salt: FieldElement,
    /// `R(SHA-256)` of each committed entry, or `0` past the last, for
    /// [`FlamingoResult::entry_hashes`].
    pub entry_hashes: [FieldElement; MAX_COMMITTED],
    /// The request's strictness, for [`FlamingoResult::strictness`].
    pub strictness: u8,
}

/// Omits the request, which carries biometric data.
impl std::fmt::Debug for FlamingoAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlamingoAttempt").finish_non_exhaustive()
    }
}

/// [`flamingo_request`] with a given `nonce_salt`.
fn flamingo_request_with_salt(
    proof_request: &ProofRequest,
    release: &ReleaseManifest,
    strictness: u8,
    images: EmbeddingSimilarityImages,
    billing_nullifier: FieldElement,
    nonce_salt: FieldElement,
    now: u64,
) -> Result<Request, AuthenticatorError> {
    let params = embedding_similarity_params(proof_request)?;
    let challenge_hash = images
        .challenge
        .as_ref()
        .map(|challenge| FieldElement::from_digest(&Sha256::digest(challenge).into()));
    if challenge_hash != params.challenge_hash {
        return Err(PrimitiveError::InvalidInput {
            attribute: "challenge".to_string(),
            reason: "must be present exactly when the request has a challenge_hash, and hash to it"
                .to_string(),
        }
        .into());
    }
    let pipeline = pipeline_for(release, &images.live_captures, strictness)?;
    let expires_at = proof_request
        .expires_at
        .min(now.saturating_add(REQUEST_LIFETIME));
    if expires_at <= now {
        return Err(RequestError::OutOfBounds("expires_at").into());
    }

    // One entry per input, in input order; `pipeline_for` matched the captures to the inputs
    // that are neither the credential nor the challenge.
    let mut credential = Some(images.credential_image);
    let mut challenge = images.challenge;
    let mut live_captures = images.live_captures.into_iter().map(|capture| capture.data);
    let entries = pipeline
        .inputs
        .iter()
        .map(|input| match input.role.as_str() {
            CREDENTIAL => credential.take(),
            CHALLENGE => challenge.take(),
            _ => live_captures.next(),
        })
        .collect();
    let payload = Payload {
        pipeline_id: pipeline.pipeline_id,
        strictness,
        entries,
    };
    Ok(Request::new(
        proof_request.rp_id.into(),
        flamingo_nonce(proof_request.nonce, nonce_salt),
        expires_at,
        billing_nullifier,
        &payload,
        None,
    )?)
}

/// The first pipeline of [`PIPELINE_TYPE`] that takes exactly `captures` and lists `strictness`.
fn pipeline_for<'a>(
    release: &'a ReleaseManifest,
    captures: &[LiveCapture],
    strictness: u8,
) -> Result<&'a Pipeline, AuthenticatorError> {
    let mut candidates = release
        .payload()
        .pipelines
        .iter()
        .filter(|pipeline| takes_captures(pipeline, captures))
        .peekable();
    if candidates.peek().is_none() {
        return Err(AuthenticatorError::NoFlamingoPipeline);
    }
    candidates
        .find(|pipeline| pipeline.has_strictness(strictness))
        .ok_or(AuthenticatorError::StrictnessNotOffered(strictness))
}

/// Whether `pipeline` is of [`PIPELINE_TYPE`], its inputs other than the credential and the
/// challenge have the roles and labels of `captures`, in order, and its response timing stays
/// within [`MAX_RESPONSE_SLOTS`].
fn takes_captures(pipeline: &Pipeline, captures: &[LiveCapture]) -> bool {
    let mut live_inputs = pipeline
        .inputs
        .iter()
        .filter(|input| input.role != CREDENTIAL && input.role != CHALLENGE);
    pipeline.type_string == PIPELINE_TYPE
        && pipeline.response_slots.0.len() <= MAX_RESPONSE_SLOTS
        && captures.iter().all(|capture| {
            live_inputs
                .next()
                .is_some_and(|input| input.role == capture.role && input.label == capture.label)
        })
        && live_inputs.next().is_none()
}

/// The parameters of a valid Proof of Embedding Similarity request.
fn embedding_similarity_params(
    proof_request: &ProofRequest,
) -> Result<&EmbeddingSimilarityParams, AuthenticatorError> {
    proof_request.validate_proof_type()?;
    let ProofType::EmbeddingSimilarity(params) = &proof_request.proof_type else {
        return Err(PrimitiveError::InvalidInput {
            attribute: "proof_type".to_string(),
            reason: "must be embedding_similarity".to_string(),
        }
        .into());
    };
    Ok(params)
}

/// Rejects a token that does not answer the Flamingo request sent for `proof_request`, so a
/// mismatch surfaces before proving rather than as an invalid
/// token signature or, for a delivered live capture, at the RP (WIP-202 §4.4 step 5).
fn check_token_answers_request(
    claims: &FlamingoClaims,
    rp_id: FieldElement,
    rp_nonce: FieldElement,
    nonce_salt: FieldElement,
    sent_entry_hashes: &[FieldElement; MAX_COMMITTED],
    sent_strictness: u8,
    params: &EmbeddingSimilarityParams,
) -> Result<(), AuthenticatorError> {
    let mismatch = |attribute| Err(AuthenticatorError::FlamingoTokenMismatch(attribute));
    if claims.aud != rp_id {
        return mismatch("aud");
    }
    if claims.nonce != flamingo_nonce(rp_nonce, nonce_salt) {
        return mismatch("nonce");
    }
    if claims.entry_hashes[0] != sent_entry_hashes[0] {
        return mismatch("entry_hash_0");
    }
    if claims.entry_hashes[1] != sent_entry_hashes[1] {
        return mismatch("entry_hash_1");
    }
    if claims.pipeline_type != world_id_flamingo::pipeline_type(PIPELINE_TYPE) {
        return mismatch("pipeline_type");
    }
    // The proof keeps `strictness` private, so the RP sees it only through `engine_config_hash`.
    if claims.strictness != sent_strictness {
        return mismatch("strictness");
    }
    if claims.entry_hashes[2] != params.challenge_hash.unwrap_or(FieldElement::ZERO) {
        return mismatch("entry_hash_2");
    }
    if claims.entry_hashes[3] != FieldElement::ZERO {
        return mismatch("entry_hash_3");
    }
    if claims.aat.is_none() && params.aat.as_ref().is_some_and(|aat| aat.required) {
        return mismatch("aat");
    }
    Ok(())
}

/// Maps the token's AAT claims to the values the proof reveals. WIP-202 fixes
/// `min_build_version` to `0` (§4.4).
fn aat_public_values(aat: &FlamingoAatClaims) -> Result<AatPublicValues, AuthenticatorError> {
    let flags = aat.flags();
    if flags.min_build_version != 0 {
        return Err(AuthenticatorError::FlamingoTokenMismatch(
            "min_build_version",
        ));
    }
    Ok(AatPublicValues {
        trust_anchor_key_hash: aat.trust_anchor_key_hash,
        platform: flags.platform,
        sec_level: flags.sec_level,
        sec_meta: flags.sec_meta,
        authenticator_meta: flags.authenticator_meta,
    })
}

/// The billing witness the token's `billing_nullifier` needs: zeros for an RP that is not billed
/// (WIP-202 §4.6 constraint 7), the cached one otherwise.
fn billing_inputs(
    claims: &FlamingoClaims,
    billing: Option<&BillingWitness>,
) -> Result<(FieldElement, [FieldElement; 2]), AuthenticatorError> {
    if claims.billing_nullifier == FieldElement::ZERO {
        return Ok((FieldElement::ZERO, [FieldElement::ZERO; 2]));
    }
    match billing {
        Some(witness) if witness.billing_nullifier == claims.billing_nullifier => {
            Ok((witness.billing_action, witness.billing_oprf_output))
        }
        Some(_) => Err(AuthenticatorError::FlamingoTokenMismatch(
            "billing_nullifier",
        )),
        None => Err(AuthenticatorError::BillingWitnessRequired),
    }
}

impl Authenticator {
    /// Generates the [`ProofResponse`] to a Proof of Embedding Similarity request (WIP-202) from
    /// the Flamingo Verifier's result.
    ///
    /// # Typical flow
    /// ```rust,ignore
    /// // <- registration: the cached billing witness for the RP, or a billing query and
    /// //    `generate_billing_registration` without one (WIP-107 §4.6)
    /// // <- Flamingo: the thumbnail, live capture and challenge to an attested Verifier
    /// let result = authenticator
    ///     .generate_embedding_similarity_proof(&request, &flamingo, &credential, &hashes_json,
    ///         Some(&billing_witness), None, cached_seed)
    ///     .await?;
    /// // <- cache `session_id_r_seed` for a session request
    /// ```
    ///
    /// # Arguments
    /// - `proof_request`: the RP's [`ProofType::EmbeddingSimilarity`] request.
    /// - `flamingo`: the Flamingo Verifier's result for this request. Its token must answer the
    ///   request under the WIP-202 entry layout (§4.4.1).
    /// - `credential`: the PoH Credential for the request's single item, whose claim 0 commits to
    ///   `hashes_json`.
    /// - `hashes_json`: the PCP's Orb-signed `hashes.json` (WIP-202 §4.1).
    /// - `billing`: the cached billing witness of the context the token's `billing_nullifier` is
    ///   registered under. Required when the token carries one, ignored otherwise.
    /// - `account_inclusion_proof`: a cached inclusion proof if available (a fresh one will be
    ///   fetched otherwise).
    /// - `session_id_r_seed`: a cached session `r` seed for a request with an existing session.
    ///   It is re-derived through the OPRF nodes if absent.
    ///
    /// # Errors
    /// - [`AuthenticatorError::PrimitiveError`] if the request is not a valid Proof of Embedding
    ///   Similarity request.
    /// - [`AuthenticatorError::UnfullfilableRequest`] if `credential` is not for the request item.
    /// - [`AuthenticatorError::FlamingoToken`] if the token does not verify under `verifier_key`,
    ///   and [`AuthenticatorError::FlamingoTokenMismatch`] if it does not answer the request.
    /// - [`AuthenticatorError::BillingWitnessRequired`] if the token is billed and `billing` is
    ///   absent.
    /// - [`AuthenticatorError::ProofError`] if the inputs fail the circuit's checks or proving
    ///   fails.
    #[expect(clippy::too_many_arguments)]
    pub async fn generate_embedding_similarity_proof(
        &self,
        proof_request: &ProofRequest,
        flamingo: &FlamingoResult,
        credential: &CredentialInput,
        hashes_json: &[u8],
        billing: Option<&BillingWitness>,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
        session_id_r_seed: Option<FieldElement>,
    ) -> Result<ProofResult, AuthenticatorError> {
        let params = embedding_similarity_params(proof_request)?;
        // `validate_proof_type` guarantees exactly one request item.
        let item = &proof_request.requests[0];
        let cred = &credential.credential;
        if cred.issuer_schema_id != item.issuer_schema_id {
            return Err(AuthenticatorError::UnfullfilableRequest);
        }

        let claims = *flamingo.token.verify(&flamingo.verifier_key)?;
        check_token_answers_request(
            &claims,
            proof_request.rp_id.into(),
            proof_request.nonce,
            flamingo.nonce_salt,
            &flamingo.entry_hashes,
            flamingo.strictness,
            params,
        )?;
        let aat = claims.aat.as_ref().map(aat_public_values).transpose()?;
        let (billing_action, billing_oprf_output) = billing_inputs(&claims, billing)?;

        let (session_id, session_id_r_seed) = match proof_request.session_id {
            SessionRef::Existing(session_id) => {
                let seed = if let Some(seed) = session_id_r_seed {
                    session_id.verify_commitment(self.leaf_index(), seed)?;
                    seed
                } else {
                    self.build_session_id(proof_request, None, account_inclusion_proof.clone())
                        .await?
                        .1
                };
                (Some(session_id), Some(seed))
            }
            // Rejected by `validate_proof_type`.
            SessionRef::Create | SessionRef::None => (None, None),
        };

        let account = self
            .prepare_authenticator_input(account_inclusion_proof)
            .await?;
        let signal_hash = item.signal_hash();
        let message = authorization_message(claims.digest(), &flamingo.verifier_key, signal_hash);
        let signature = self
            .signer
            .offchain_signer_private_key()
            .expose_secret()
            .sign(*message);

        let input = EmbeddingSimilarityCircuitInput {
            request: EmbeddingSimilarityRequestInputs::from_request(proof_request)
                .map_err(ProofError::from)?,
            now: claims.now,
            flamingo_verifier_key: flamingo.verifier_key.clone(),
            engine_config_hash: claims.engine_config_hash,
            aat,
            cred_pk: cred.issuer.clone(),
            disclose_live_capture: params.return_live_capture,
            live_capture_hash: claims.entry_hashes[1],
            strictness: claims.strictness,
            billing_nullifier: claims.billing_nullifier,
            nonce_salt: flamingo.nonce_salt,
            token_signature: flamingo.token.signature()?,
            key_index: account.key_index,
            key_set: account.key_set.clone(),
            inclusion_proof: account.inclusion_proof.clone(),
            signature,
            claims: credential_claims(cred)?,
            associated_data_hash: cred.associated_data_commitment,
            genesis_issued_at: cred.genesis_issued_at,
            expires_at: cred.expires_at,
            sub_blinding_factor: credential.blinding_factor,
            credential_id: cred.id,
            issuer_version: cred.issuer_version,
            credential_signature: cred
                .signature
                .clone()
                .ok_or(AuthenticatorError::InvalidCredentialForProofRequest)?,
            hashes_json: hashes_json.to_vec(),
            session_id_r: session_id_r_seed.unwrap_or(FieldElement::ZERO),
            billing_action,
            billing_oprf_output,
        };
        let proof = generate_embedding_similarity_proof(input, self.zk_artifact_source.as_ref())?;

        let proof_response = ProofResponse {
            id: proof_request.id.clone(),
            version: proof_request.version,
            session_id,
            error: None,
            responses: Vec::new(),
            embedding_similarity: Some(EmbeddingSimilarityResponseItem {
                identifier: item.identifier.clone(),
                proof,
                signing_key_attestation: flamingo.signing_key_attestation.clone(),
            }),
        };
        proof_request.validate_response(&proof_response)?;
        Ok(ProofResult {
            session_id_r_seed,
            proof_response,
        })
    }
}

/// The Credential's claims as the circuit's fixed-size array.
fn credential_claims(
    credential: &Credential,
) -> Result<[FieldElement; Credential::MAX_CLAIMS], AuthenticatorError> {
    credential
        .claims
        .clone()
        .try_into()
        .map_err(|_| AuthenticatorError::InvalidCredentialForProofRequest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Signature, U160, U256};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use world_id_flamingo::release_manifest::{Input, ManifestPayload, ResponseSlots};
    use world_id_primitives::{
        OprfKeyId, RequestItem, RequestVersion, authenticator_assertion::AatRequirements,
        oprf::OprfPrefix, rp::RpId,
    };

    fn claims() -> FlamingoClaims {
        FlamingoClaims {
            now: 1_700_000_000,
            entry_hashes: [
                FieldElement::from(1u64),
                FieldElement::from(2u64),
                FieldElement::from(3u64),
                FieldElement::ZERO,
            ],
            aud: FieldElement::from(9u64),
            nonce: flamingo_nonce(FieldElement::from(5u64), FieldElement::from(NONCE_SALT)),
            aat: None,
            engine_config_hash: FieldElement::from(4u64),
            pipeline_type: world_id_flamingo::pipeline_type(PIPELINE_TYPE),
            strictness: 2,
            billing_nullifier: FieldElement::ZERO,
        }
    }

    #[test]
    fn aat_flags_unpack_into_the_public_values() {
        let aat = FlamingoAatClaims {
            trust_anchor_key_hash: FieldElement::from(7u64),
            aat_flags: 2 + (3 << 8) + (0xA << 48) + (0x13 << 52),
        };
        assert_eq!(
            aat_public_values(&aat).unwrap(),
            AatPublicValues {
                trust_anchor_key_hash: FieldElement::from(7u64),
                platform: 2,
                sec_level: 3,
                sec_meta: 0xA,
                authenticator_meta: 0x13,
            }
        );
    }

    #[test]
    fn a_min_build_version_is_rejected() {
        let aat = FlamingoAatClaims {
            trust_anchor_key_hash: FieldElement::ZERO,
            aat_flags: 1 << 16,
        };
        assert!(matches!(
            aat_public_values(&aat),
            Err(AuthenticatorError::FlamingoTokenMismatch(
                "min_build_version"
            ))
        ));
    }

    #[test]
    fn an_unbilled_token_needs_no_witness() {
        assert_eq!(
            billing_inputs(&claims(), None).unwrap(),
            (FieldElement::ZERO, [FieldElement::ZERO; 2])
        );
    }

    #[test]
    fn a_billed_token_needs_its_own_witness() {
        let mut claims = claims();
        claims.billing_nullifier = FieldElement::from(11u64);
        let witness = BillingWitness {
            billing_action: FieldElement::from(12u64),
            billing_nullifier: FieldElement::from(11u64),
            billing_oprf_output: [FieldElement::from(13u64), FieldElement::from(14u64)],
        };
        assert_eq!(
            billing_inputs(&claims, Some(&witness)).unwrap(),
            (witness.billing_action, witness.billing_oprf_output)
        );
        assert!(matches!(
            billing_inputs(&claims, None),
            Err(AuthenticatorError::BillingWitnessRequired)
        ));
        let other = BillingWitness {
            billing_nullifier: FieldElement::from(99u64),
            ..witness
        };
        assert!(matches!(
            billing_inputs(&claims, Some(&other)),
            Err(AuthenticatorError::FlamingoTokenMismatch(
                "billing_nullifier"
            ))
        ));
    }

    fn params(aat: Option<AatRequirements>) -> EmbeddingSimilarityParams {
        EmbeddingSimilarityParams {
            action: FieldElement::ZERO,
            challenge_hash: Some(FieldElement::from(3u64)),
            return_live_capture: false,
            aat,
        }
    }

    fn check(
        claims: &FlamingoClaims,
        params: &EmbeddingSimilarityParams,
    ) -> Result<(), &'static str> {
        check_token_answers_request(
            claims,
            FieldElement::from(9u64),
            FieldElement::from(5u64),
            FieldElement::from(NONCE_SALT),
            &self::claims().entry_hashes,
            2,
            params,
        )
        .map_err(|err| match err {
            AuthenticatorError::FlamingoTokenMismatch(attribute) => attribute,
            other => panic!("unexpected error: {other}"),
        })
    }

    #[test]
    fn a_token_for_the_request_is_accepted() {
        assert_eq!(check(&claims(), &params(None)), Ok(()));
    }

    #[test]
    fn a_request_without_a_challenge_takes_a_token_without_one() {
        let mut no_challenge = params(None);
        no_challenge.challenge_hash = None;
        assert_eq!(check(&claims(), &no_challenge), Err("entry_hash_2"));
        let mut claims = claims();
        claims.entry_hashes[2] = FieldElement::ZERO;
        assert_eq!(check(&claims, &no_challenge), Ok(()));
    }

    #[test]
    fn a_token_for_another_request_is_rejected() {
        type Tamper = fn(&mut FlamingoClaims);
        let cases: [(&str, Tamper); 8] = [
            ("aud", |c| c.aud = FieldElement::from(10u64)),
            // A token over the RP's own nonce rather than the derived one.
            ("nonce", |c| c.nonce = FieldElement::from(5u64)),
            ("pipeline_type", |c| {
                c.pipeline_type = FieldElement::from(8u64);
            }),
            ("strictness", |c| c.strictness = 1),
            ("entry_hash_0", |c| {
                c.entry_hashes[0] = FieldElement::from(8u64);
            }),
            ("entry_hash_1", |c| {
                c.entry_hashes[1] = FieldElement::from(8u64);
            }),
            ("entry_hash_2", |c| {
                c.entry_hashes[2] = FieldElement::from(8u64);
            }),
            ("entry_hash_3", |c| {
                c.entry_hashes[3] = FieldElement::from(8u64);
            }),
        ];
        for (attribute, tamper) in cases {
            let mut claims = claims();
            tamper(&mut claims);
            assert_eq!(check(&claims, &params(None)), Err(attribute));
        }
    }

    #[test]
    fn a_required_aat_must_be_present() {
        let required = params(Some(AatRequirements { required: true }));
        assert_eq!(check(&claims(), &required), Err("aat"));
        let mut claims = claims();
        claims.aat = Some(FlamingoAatClaims {
            trust_anchor_key_hash: FieldElement::from(7u64),
            aat_flags: 0,
        });
        assert_eq!(check(&claims, &required), Ok(()));
    }

    const NOW: u64 = 1_783_446_000;
    const NONCE_SALT: u64 = 13;

    fn image_hash(bytes: &[u8]) -> FieldElement {
        FieldElement::from_digest(&Sha256::digest(bytes).into())
    }

    fn capture(role: &str, label: &str, data: &[u8]) -> LiveCapture {
        LiveCapture {
            role: role.into(),
            label: label.into(),
            data: data.to_vec(),
        }
    }

    fn images() -> EmbeddingSimilarityImages {
        EmbeddingSimilarityImages {
            credential_image: b"credential image".to_vec(),
            live_captures: vec![capture(LIVE, "front_frame", b"live image")],
            challenge: Some(b"challenge image".to_vec()),
        }
    }

    /// The images of a two-frame `LightGuard` capture: the lit frame is matched, the unlit one
    /// only checked.
    fn light_guard_images() -> EmbeddingSimilarityImages {
        EmbeddingSimilarityImages {
            live_captures: vec![
                capture(LIVE, "lit_frame", b"live image"),
                capture(EVIDENCE, "unlit_frame", b"unlit frame"),
            ],
            ..images()
        }
    }

    fn proof_request() -> ProofRequest {
        let action = FieldElement::try_from(
            U256::from(7u64) | (U256::from(OprfPrefix::EmbeddingSimilarity as u8) << 248),
        )
        .unwrap();
        ProofRequest {
            id: "req_es".into(),
            version: RequestVersion::V1,
            proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
                action,
                challenge_hash: Some(image_hash(b"challenge image")),
                return_live_capture: false,
                aat: None,
            }),
            created_at: NOW - 60,
            expires_at: NOW + 240,
            rp_id: RpId::new(1_928_118),
            oprf_key_id: OprfKeyId::new(U160::from(1u64)),
            session_id: SessionRef::None,
            signature: Signature::new(U256::ZERO, U256::ZERO, false),
            nonce: FieldElement::from(42u64),
            requests: vec![RequestItem::embedding_similarity(
                "poh".into(),
                None,
                None,
                None,
            )],
            constraints: None,
        }
    }

    fn proof_request_without_a_challenge() -> ProofRequest {
        let mut request = proof_request();
        let ProofType::EmbeddingSimilarity(params) = &mut request.proof_type else {
            unreachable!()
        };
        params.challenge_hash = None;
        request
    }

    fn input(role: &str, label: &str) -> Input {
        Input {
            role: role.into(),
            label: label.into(),
            media_types: vec!["image/jpeg".into()],
        }
    }

    /// A WIP-202 pipeline with the credential first, then `captures` as `(role, label)`, then the
    /// challenge.
    fn pipeline(pipeline_id: u16, captures: &[(&str, &str)]) -> Pipeline {
        let mut inputs = vec![input(CREDENTIAL, "orb_thumbnail")];
        inputs.extend(captures.iter().map(|(role, label)| input(role, label)));
        inputs.push(input(CHALLENGE, "stream_frame"));
        Pipeline {
            pipeline_id,
            type_string: PIPELINE_TYPE.into(),
            strictness_levels: vec![1, 2],
            inputs,
            response_slots: ResponseSlots(vec![500, 1587, 5039, 16_000]),
        }
    }

    fn front_frame(pipeline_id: u16) -> Pipeline {
        pipeline(pipeline_id, &[(LIVE, "front_frame")])
    }

    fn light_guard(pipeline_id: u16) -> Pipeline {
        pipeline(
            pipeline_id,
            &[(LIVE, "lit_frame"), (EVIDENCE, "unlit_frame")],
        )
    }

    /// A manifest with `pipelines`. Authenticators do not verify its signature, so it has none.
    fn release(pipelines: Vec<Pipeline>) -> ReleaseManifest {
        let payload = ManifestPayload {
            iss: "https://engines.example.com".into(),
            engine_hash: [0x2a; 48],
            version: 1,
            pipelines,
            errors: std::collections::BTreeMap::new(),
        };
        let header = r#"{"alg":"ES256","kid":"release-1","typ":"world-id-engine-manifest"}"#;
        let jws = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        ReleaseManifest::from_jws(&jws).unwrap()
    }

    fn build_with(
        proof_request: &ProofRequest,
        release: &ReleaseManifest,
        strictness: u8,
        images: EmbeddingSimilarityImages,
    ) -> Result<Request, AuthenticatorError> {
        flamingo_request_with_salt(
            proof_request,
            release,
            strictness,
            images,
            FieldElement::from(11u64),
            FieldElement::from(NONCE_SALT),
            NOW,
        )
    }

    fn build(release: &ReleaseManifest, strictness: u8) -> Result<Request, AuthenticatorError> {
        build_with(&proof_request(), release, strictness, images())
    }

    fn entry_hashes(request: &Request, release: &ReleaseManifest) -> [FieldElement; MAX_COMMITTED] {
        request
            .payload()
            .unwrap()
            .fit(release)
            .unwrap()
            .entry_hashes
    }

    #[test]
    fn the_request_fills_entries_in_input_order() {
        // Only the second pipeline takes a single front frame.
        let release = release(vec![light_guard(1), front_frame(2)]);
        let request = build(&release, 2).unwrap();
        let payload = request.payload().unwrap();
        assert_eq!((payload.pipeline_id, payload.strictness), (2, 2));
        assert_eq!(
            payload.entries,
            [
                Some(b"credential image".to_vec()),
                Some(b"live image".to_vec()),
                Some(b"challenge image".to_vec()),
            ]
        );
        assert_eq!(
            entry_hashes(&request, &release),
            [
                image_hash(b"credential image"),
                image_hash(b"live image"),
                image_hash(b"challenge image"),
                FieldElement::ZERO,
            ]
        );
        assert_eq!(request.billing_nullifier, FieldElement::from(11u64));
        assert!(request.aat_inputs.is_none());
    }

    #[test]
    fn aud_nonce_and_expiry_come_from_the_proof_request() {
        let request = build(&release(vec![front_frame(1)]), 1).unwrap();
        assert_eq!(request.aud, FieldElement::from(1_928_118u64));
        assert_eq!(
            request.nonce,
            flamingo_nonce(FieldElement::from(42u64), FieldElement::from(NONCE_SALT))
        );
        assert_eq!(request.expires_at, NOW + 240);
        assert_eq!(request.check_expiry(NOW), Ok(()));
    }

    #[test]
    fn each_attempt_derives_its_nonce_from_a_fresh_salt() {
        let release = release(vec![front_frame(1)]);
        let attempt = || {
            flamingo_request(
                &proof_request(),
                &release,
                1,
                images(),
                FieldElement::from(11u64),
                NOW,
            )
            .unwrap()
        };
        let (first, retry) = (attempt(), attempt());
        assert_ne!(first.nonce_salt, retry.nonce_salt);
        for attempt in [&first, &retry] {
            assert_eq!(
                attempt.request.nonce,
                flamingo_nonce(FieldElement::from(42u64), attempt.nonce_salt)
            );
            assert_eq!(attempt.strictness, 1);
            assert_eq!(
                attempt.entry_hashes,
                entry_hashes(&attempt.request, &release)
            );
        }
    }

    #[test]
    fn the_expiry_leaves_room_for_a_device_clock_ahead_of_the_verifier() {
        let release = release(vec![front_frame(1)]);
        let mut proof_request = proof_request();
        proof_request.expires_at = NOW + 3600;
        let request = build_with(&proof_request, &release, 1, images()).unwrap();
        assert_eq!(request.expires_at, NOW + REQUEST_LIFETIME);
        let verifier_behind = NOW - (MAX_REQUEST_LIFETIME - REQUEST_LIFETIME);
        assert_eq!(request.check_expiry(verifier_behind), Ok(()));
        assert!(request.check_expiry(verifier_behind - 1).is_err());

        proof_request.expires_at = NOW;
        assert!(matches!(
            build_with(&proof_request, &release, 1, images()),
            Err(AuthenticatorError::FlamingoRequest(
                RequestError::OutOfBounds("expires_at")
            ))
        ));
    }

    #[test]
    fn a_release_without_a_pipeline_for_the_captures_is_rejected() {
        let mut slow = front_frame(1);
        slow.response_slots = ResponseSlots((1..=9).map(|i| i * 1000).collect());
        let mut other_type = front_frame(2);
        other_type.type_string = "OTHER<2>(credential#,live#,challenge#?,evidence*)".into();
        let release = release(vec![slow, other_type, light_guard(3)]);
        assert!(matches!(
            build(&release, 1),
            Err(AuthenticatorError::NoFlamingoPipeline)
        ));
    }

    #[test]
    fn the_first_pipeline_listing_the_strictness_is_chosen() {
        let mut strict_only = front_frame(1);
        strict_only.strictness_levels = vec![2];
        let release = release(vec![strict_only, front_frame(2)]);
        assert_eq!(
            build(&release, 1).unwrap().payload().unwrap().pipeline_id,
            2
        );
        assert_eq!(
            build(&release, 2).unwrap().payload().unwrap().pipeline_id,
            1
        );
        assert!(matches!(
            build(&release, 3),
            Err(AuthenticatorError::StrictnessNotOffered(3))
        ));
    }

    #[test]
    fn a_request_without_a_challenge_leaves_its_entry_absent() {
        let release = release(vec![front_frame(1)]);
        let mut images = images();
        images.challenge = None;
        let request =
            build_with(&proof_request_without_a_challenge(), &release, 1, images).unwrap();
        assert_eq!(request.payload().unwrap().entries[2], None);
        assert_eq!(
            entry_hashes(&request, &release),
            [
                image_hash(b"credential image"),
                image_hash(b"live image"),
                FieldElement::ZERO,
                FieldElement::ZERO,
            ]
        );
    }

    #[test]
    fn a_challenge_that_does_not_match_the_request_is_rejected() {
        let mut other = images();
        other.challenge = Some(b"other image".to_vec());
        let mut missing = images();
        missing.challenge = None;
        let cases = [
            (proof_request(), other),
            (proof_request(), missing),
            (proof_request_without_a_challenge(), images()),
        ];
        for (proof_request, images) in cases {
            assert!(matches!(
                build_with(&proof_request, &release(vec![front_frame(1)]), 1, images),
                Err(AuthenticatorError::PrimitiveError(PrimitiveError::InvalidInput { attribute, .. }))
                    if attribute == "challenge"
            ));
        }
    }

    #[test]
    fn a_light_guard_capture_selects_its_pipeline_and_commits_only_the_lit_frame() {
        let release = release(vec![front_frame(1), light_guard(2)]);
        for (proof_request, challenge) in [
            (proof_request(), Some(b"challenge image".to_vec())),
            (proof_request_without_a_challenge(), None),
        ] {
            let images = EmbeddingSimilarityImages {
                challenge: challenge.clone(),
                ..light_guard_images()
            };
            let request = build_with(&proof_request, &release, 1, images).unwrap();
            let payload = request.payload().unwrap();
            assert_eq!(payload.pipeline_id, 2);
            assert_eq!(
                payload.entries,
                [
                    Some(b"credential image".to_vec()),
                    Some(b"live image".to_vec()),
                    Some(b"unlit frame".to_vec()),
                    challenge.clone(),
                ]
            );
            assert_eq!(
                entry_hashes(&request, &release),
                [
                    image_hash(b"credential image"),
                    image_hash(b"live image"),
                    challenge.map_or(FieldElement::ZERO, |challenge| image_hash(&challenge)),
                    FieldElement::ZERO,
                ]
            );
        }
    }

    #[test]
    fn the_live_role_is_committed_wherever_its_input_is() {
        let release = release(vec![pipeline(
            1,
            &[(EVIDENCE, "unlit_frame"), (LIVE, "lit_frame")],
        )]);
        let mut evidence_first = light_guard_images();
        evidence_first.live_captures.reverse();
        let request = build_with(&proof_request(), &release, 1, evidence_first).unwrap();
        let payload = request.payload().unwrap();
        assert_eq!(payload.entries[1].as_deref(), Some(&b"unlit frame"[..]));
        assert_eq!(
            entry_hashes(&request, &release)[1],
            image_hash(b"live image")
        );

        // The captures must come in the pipeline's input order.
        assert!(matches!(
            build_with(&proof_request(), &release, 1, light_guard_images()),
            Err(AuthenticatorError::NoFlamingoPipeline)
        ));
    }

    #[test]
    fn captures_without_a_pipeline_of_their_roles_and_labels_are_rejected() {
        let release = release(vec![light_guard(1)]);
        let mut extra = light_guard_images();
        extra
            .live_captures
            .push(capture(EVIDENCE, "depth_map", b"depth"));
        let mut relabeled = light_guard_images();
        relabeled.live_captures[1].label = "depth_map".into();
        let mut recast = light_guard_images();
        recast.live_captures[1].role = LIVE.into();
        let mut empty = images();
        empty.live_captures.clear();
        for images in [images(), extra, relabeled, recast, empty] {
            assert!(matches!(
                build_with(&proof_request(), &release, 1, images),
                Err(AuthenticatorError::NoFlamingoPipeline)
            ));
        }
    }
}
