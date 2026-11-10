//! The Authenticator's side of the WIP-202 Proof of Embedding Similarity: from the Flamingo
//! Verifier's result to the [`ProofResponse`] for the RP.

use alloy::primitives::Bytes;
use eddsa_babyjubjub::EdDSAPublicKey;
use secrecy::ExposeSecret as _;
use world_id_flamingo::{FlamingoAatClaims, FlamingoClaims, FlamingoToken};
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

/// Bits 16-47 of `aat_flags`: `min_build_version`, which WIP-202 fixes to `0` (§4.4).
const MIN_BUILD_VERSION_MASK: u64 = 0xFFFF_FFFF << 16;

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

/// Unpacks the token's AAT claims into the values the proof reveals.
fn aat_public_values(aat: &FlamingoAatClaims) -> Result<AatPublicValues, AuthenticatorError> {
    let flags = aat.aat_flags;
    if flags & MIN_BUILD_VERSION_MASK != 0 {
        return Err(AuthenticatorError::FlamingoTokenMismatch(
            "min_build_version",
        ));
    }
    // Truncation keeps each sub-field; the Verifier range-checked them (WIP-201 §4.7 check 3).
    #[expect(clippy::cast_possible_truncation)]
    Ok(AatPublicValues {
        trust_anchor_key_hash: aat.trust_anchor_key_hash,
        platform: flags as u8,
        sec_level: (flags >> 8) as u8,
        sec_meta: ((flags >> 48) & 0xF) as u8,
        authenticator_meta: ((flags >> 52) & 0x1F) as u8,
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
        proof_request.validate_proof_type()?;
        let ProofType::EmbeddingSimilarity(params) = &proof_request.proof_type else {
            return Err(PrimitiveError::InvalidInput {
                attribute: "proof_type".to_string(),
                reason: "must be embedding_similarity".to_string(),
            }
            .into());
        };
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
    use world_id_primitives::authenticator_assertion::AatRequirements;

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
        let required = params(Some(AatRequirements {
            required: true,
            ..AatRequirements::default()
        }));
        assert_eq!(check(&claims(), &required), Err("aat"));
        let mut claims = claims();
        claims.aat = Some(FlamingoAatClaims {
            trust_anchor_key_hash: FieldElement::from(7u64),
            aat_flags: 0,
        });
        assert_eq!(check(&claims, &required), Ok(()));
    }
}
