//! The Authenticator's side of the WIP-202 Proof of Embedding Similarity: from the request it
//! sends the Flamingo Verifier to the [`ProofResponse`] for the RP.

use alloy::primitives::Bytes;
use eddsa_babyjubjub::EdDSAPublicKey;
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};
use world_id_flamingo::{
    Entry, FlamingoAatClaims, FlamingoClaims, FlamingoToken, MAX_REQUEST_LIFETIME, Payload,
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
        COMPARE_SOURCES, authorization_message, generate_embedding_similarity_proof,
    },
};

use crate::{
    api_types::AccountInclusionProof,
    authenticator::{Authenticator, CredentialInput, ProofResult},
    error::AuthenticatorError,
};

/// What the Flamingo Verifier returned for a Proof of Embedding Similarity request (WIP-201
/// §4.4.1), after the Authenticator checked its attestation (WIP-201 §4.6).
#[derive(Debug, Clone)]
pub struct FlamingoResult {
    /// The Flamingo Token the Verifier signed.
    pub token: FlamingoToken,
    /// The Verifier's signing key, as `signing_key_attestation` attests it.
    pub verifier_key: EdDSAPublicKey,
    /// The attestation of `verifier_key`, forwarded to the RP (WIP-201 §4.7 check 1).
    pub signing_key_attestation: Bytes,
}

/// The images a Proof of Embedding Similarity compares, in the order of the WIP-202 entry layout
/// (§4.3).
#[derive(Clone)]
pub struct EmbeddingSimilarityImages {
    /// The PCP thumbnail that the Credential's `hashes.json` lists.
    pub credential_image: Vec<u8>,
    /// The live capture, the pipeline's only input.
    pub live_capture: Vec<u8>,
    /// The RP's challenge image, whose `R(SHA-256)` is the request's `challenge_hash`.
    pub challenge: Vec<u8>,
}

/// Omits the images, which are biometric data.
impl std::fmt::Debug for EmbeddingSimilarityImages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingSimilarityImages")
            .finish_non_exhaustive()
    }
}

/// The role WIP-202 requires of the pipeline's only input (§4.3).
const LIVE_FRAME: &str = "live_frame";

/// Most response release times a chosen pipeline may list, so a response's timing reveals at most
/// 3 bits (WIP-201 §4.6).
const MAX_RESPONSE_SLOTS: usize = 8;

/// How long after the device's `now` a request may expire. The Verifier rejects one expiring more
/// than `MAX_REQUEST_LIFETIME` after its own clock, so the other half absorbs a device clock that
/// runs ahead of it.
const REQUEST_LIFETIME: u64 = MAX_REQUEST_LIFETIME / 2;

/// Builds the Flamingo request (WIP-201 §4.4.1) for a Proof of Embedding Similarity request, under
/// the WIP-202 entry layout (§4.3).
///
/// The pipeline is the first in `release` with a single `live_frame` input, so only the release,
/// not the Verifier, picks it. The result carries no `aat_inputs`: an AAT signs the request's
/// [`Request::cdh`], so the caller obtains one for this request and sets it afterwards.
///
/// # Arguments
/// - `proof_request`: the RP's [`ProofType::EmbeddingSimilarity`] request.
/// - `release`: the release manifest the Verifier's attestation binds (WIP-201 §4.6). The
///   attestation binds the manifest but does not vouch for it, so it MUST also verify under a
///   release key of an Engine Provider the caller trusts (§4.3.4).
/// - `match_strictness`: the Authenticator Provider's level; WIP-202 requests set none.
/// - `images`: the entries to compare; the challenge must hash to the request's `challenge_hash`.
/// - `billing_nullifier`: the WIP-107 `billingNullifier` registered for the RP, or `0`.
/// - `now`: the device's time, in Unix seconds. `expires_at` is the request's expiry capped at
///   `now + MAX_REQUEST_LIFETIME / 2`, so a device clock up to `MAX_REQUEST_LIFETIME / 2` ahead of
///   the Verifier's does not get the request rejected.
///
/// # Errors
/// - [`AuthenticatorError::PrimitiveError`] if the request is not a valid Proof of Embedding
///   Similarity request, or the challenge does not hash to its `challenge_hash`.
/// - [`AuthenticatorError::NoFlamingoPipeline`] if `release` has no usable pipeline.
/// - [`AuthenticatorError::MatchStrictnessNotOffered`] if `release` does not list
///   `match_strictness`.
/// - [`AuthenticatorError::FlamingoRequest`] if the request has expired at `now`, or an entry is
///   out of bounds.
pub fn flamingo_request(
    proof_request: &ProofRequest,
    release: &ReleaseManifest,
    match_strictness: u8,
    images: EmbeddingSimilarityImages,
    billing_nullifier: FieldElement,
    now: u64,
) -> Result<Request, AuthenticatorError> {
    let params = embedding_similarity_params(proof_request)?;
    if FieldElement::from_digest(&Sha256::digest(&images.challenge).into()) != params.challenge_hash
    {
        return Err(PrimitiveError::InvalidInput {
            attribute: "challenge".to_string(),
            reason: "must hash to the request's challenge_hash".to_string(),
        }
        .into());
    }
    let pipeline = release
        .payload()
        .pipelines
        .iter()
        .find(|pipeline| is_live_frame_pipeline(pipeline))
        .ok_or(AuthenticatorError::NoFlamingoPipeline)?;
    if !release.has_match_strictness(match_strictness) {
        return Err(AuthenticatorError::MatchStrictnessNotOffered(
            match_strictness,
        ));
    }
    let expires_at = proof_request
        .expires_at
        .min(now.saturating_add(REQUEST_LIFETIME));
    if expires_at <= now {
        return Err(RequestError::OutOfBounds("expires_at").into());
    }

    let entries = [
        images.credential_image,
        images.live_capture,
        images.challenge,
    ]
    .map(|data| Entry { data, meta: vec![] });
    let payload = Payload {
        pipeline_id: pipeline.pipeline_id,
        match_strictness,
        hints: vec![],
        entries: entries.into(),
        pipeline_inputs: vec![1],
        compare: vec![0, 1, 2],
    };
    Ok(Request::new(
        proof_request.rp_id.into(),
        proof_request.nonce,
        expires_at,
        billing_nullifier,
        &payload,
        None,
    )?)
}

/// Whether WIP-202 can use `pipeline`: its only input is a live frame, and its response timing
/// stays within [`MAX_RESPONSE_SLOTS`].
fn is_live_frame_pipeline(pipeline: &Pipeline) -> bool {
    matches!(pipeline.inputs.as_slice(), [input] if input.role == LIVE_FRAME)
        && pipeline.response_slots.0.len() <= MAX_RESPONSE_SLOTS
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

/// Rejects a token that does not answer `proof_request` under the WIP-202 entry layout (§4.3), so
/// a mismatch surfaces before proving rather than as an invalid token signature.
fn check_token_answers_request(
    claims: &FlamingoClaims,
    rp_id: FieldElement,
    nonce: FieldElement,
    params: &EmbeddingSimilarityParams,
) -> Result<(), AuthenticatorError> {
    let mismatch = |attribute| Err(AuthenticatorError::FlamingoTokenMismatch(attribute));
    if claims.aud != rp_id {
        return mismatch("aud");
    }
    if claims.nonce != nonce {
        return mismatch("nonce");
    }
    if claims.compare_sources != COMPARE_SOURCES {
        return mismatch("compare_sources");
    }
    if claims.compared_entry_hashes[2] != params.challenge_hash {
        return mismatch("compared_entry_hash_2");
    }
    if claims.compared_entry_hashes[3] != FieldElement::ZERO {
        return mismatch("compared_entry_hash_3");
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
    ///   request under the WIP-202 entry layout (§4.3).
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
            request: EmbeddingSimilarityRequestInputs::from_request(
                proof_request,
                cred.issuer_version,
            )
            .map_err(ProofError::from)?,
            now: claims.now,
            flamingo_verifier_key: flamingo.verifier_key.clone(),
            engine_config_hash: claims.engine_config_hash,
            aat,
            cred_pk: cred.issuer.clone(),
            live_capture_hash: claims.compared_entry_hashes[1],
            billing_nullifier: claims.billing_nullifier,
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
            compared_entry_hashes: [
                FieldElement::from(1u64),
                FieldElement::from(2u64),
                FieldElement::from(3u64),
                FieldElement::ZERO,
            ],
            aud: FieldElement::from(9u64),
            nonce: FieldElement::from(5u64),
            aat: None,
            compare_sources: COMPARE_SOURCES,
            engine_config_hash: FieldElement::from(4u64),
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
            challenge_hash: FieldElement::from(3u64),
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
    fn a_token_for_another_request_is_rejected() {
        type Tamper = fn(&mut FlamingoClaims);
        let cases: [(&str, Tamper); 5] = [
            ("aud", |c| c.aud = FieldElement::from(10u64)),
            ("nonce", |c| c.nonce = FieldElement::from(6u64)),
            ("compare_sources", |c| c.compare_sources = 0),
            ("compared_entry_hash_2", |c| {
                c.compared_entry_hashes[2] = FieldElement::from(8u64);
            }),
            ("compared_entry_hash_3", |c| {
                c.compared_entry_hashes[3] = FieldElement::from(8u64);
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

    fn image_hash(bytes: &[u8]) -> FieldElement {
        FieldElement::from_digest(&Sha256::digest(bytes).into())
    }

    fn images() -> EmbeddingSimilarityImages {
        EmbeddingSimilarityImages {
            credential_image: b"credential image".to_vec(),
            live_capture: b"live image".to_vec(),
            challenge: b"challenge image".to_vec(),
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
                challenge_hash: image_hash(b"challenge image"),
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

    fn pipeline(pipeline_id: u16, roles: &[&str]) -> Pipeline {
        Pipeline {
            pipeline_id,
            inputs: roles
                .iter()
                .map(|role| Input {
                    role: (*role).into(),
                    media_types: vec!["image/jpeg".into()],
                })
                .collect(),
            response_slots: ResponseSlots(vec![500, 1587, 5039, 16_000]),
        }
    }

    /// A manifest with `pipelines`. Authenticators do not verify its signature, so it has none.
    fn release(pipelines: Vec<Pipeline>) -> ReleaseManifest {
        let payload = ManifestPayload {
            iss: "https://engines.example.com".into(),
            engine_hash: [0x2a; 48],
            version: 1,
            match_strictness_levels: vec![1, 2],
            pipelines,
        };
        let header = r#"{"alg":"ES256","kid":"release-1","typ":"world-id-engine-manifest"}"#;
        let jws = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        ReleaseManifest::from_jws(&jws).unwrap()
    }

    fn build(
        release: &ReleaseManifest,
        match_strictness: u8,
    ) -> Result<Request, AuthenticatorError> {
        flamingo_request(
            &proof_request(),
            release,
            match_strictness,
            images(),
            FieldElement::from(11u64),
            NOW,
        )
    }

    #[test]
    fn the_request_follows_the_entry_layout() {
        // Only the second pipeline has a single live frame input.
        let release = release(vec![
            pipeline(1, &["live_frame", "live_frame"]),
            pipeline(2, &["live_frame"]),
        ]);
        let request = build(&release, 2).unwrap();
        let payload = request.payload().unwrap();
        assert_eq!((payload.pipeline_id, payload.match_strictness), (2, 2));
        assert_eq!(
            payload.compare_sources(release.pipeline(2).unwrap()),
            Ok(COMPARE_SOURCES)
        );
        assert_eq!(
            payload.compared_entry_hashes(),
            [
                image_hash(b"credential image"),
                image_hash(b"live image"),
                image_hash(b"challenge image"),
                FieldElement::ZERO,
            ]
        );
        assert!(payload.entries.iter().all(|entry| entry.meta.is_empty()));
        assert_eq!(request.billing_nullifier, FieldElement::from(11u64));
        assert!(request.aat_inputs.is_none());
    }

    #[test]
    fn aud_nonce_and_expiry_come_from_the_proof_request() {
        let request = build(&release(vec![pipeline(1, &["live_frame"])]), 1).unwrap();
        assert_eq!(request.aud, FieldElement::from(1_928_118u64));
        assert_eq!(request.nonce, FieldElement::from(42u64));
        assert_eq!(request.expires_at, NOW + 240);
        assert_eq!(request.check_expiry(NOW), Ok(()));
    }

    #[test]
    fn the_expiry_leaves_room_for_a_device_clock_ahead_of_the_verifier() {
        let release = release(vec![pipeline(1, &["live_frame"])]);
        let mut proof_request = proof_request();
        proof_request.expires_at = NOW + 3600;
        let request = flamingo_request(
            &proof_request,
            &release,
            1,
            images(),
            FieldElement::ZERO,
            NOW,
        )
        .unwrap();
        assert_eq!(request.expires_at, NOW + REQUEST_LIFETIME);
        let verifier_behind = NOW - (MAX_REQUEST_LIFETIME - REQUEST_LIFETIME);
        assert_eq!(request.check_expiry(verifier_behind), Ok(()));
        assert!(request.check_expiry(verifier_behind - 1).is_err());

        proof_request.expires_at = NOW;
        assert!(matches!(
            flamingo_request(
                &proof_request,
                &release,
                1,
                images(),
                FieldElement::ZERO,
                NOW
            ),
            Err(AuthenticatorError::FlamingoRequest(
                RequestError::OutOfBounds("expires_at")
            ))
        ));
    }

    #[test]
    fn a_release_without_a_live_frame_pipeline_is_rejected() {
        let mut slow = pipeline(3, &["live_frame"]);
        slow.response_slots = ResponseSlots((1..=9).map(|i| i * 1000).collect());
        let release = release(vec![
            pipeline(1, &["document"]),
            pipeline(2, &["live_frame", "live_frame"]),
            slow,
        ]);
        assert!(matches!(
            build(&release, 1),
            Err(AuthenticatorError::NoFlamingoPipeline)
        ));
    }

    #[test]
    fn an_unlisted_match_strictness_is_rejected() {
        assert!(matches!(
            build(&release(vec![pipeline(1, &["live_frame"])]), 3),
            Err(AuthenticatorError::MatchStrictnessNotOffered(3))
        ));
    }

    #[test]
    fn another_challenge_is_rejected() {
        let mut images = images();
        images.challenge = b"other image".to_vec();
        assert!(matches!(
            flamingo_request(
                &proof_request(),
                &release(vec![pipeline(1, &["live_frame"])]),
                1,
                images,
                FieldElement::ZERO,
                NOW,
            ),
            Err(AuthenticatorError::PrimitiveError(PrimitiveError::InvalidInput { attribute, .. }))
                if attribute == "challenge"
        ));
    }
}
