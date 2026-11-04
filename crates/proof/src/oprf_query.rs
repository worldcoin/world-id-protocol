//! Shared helpers for generating query proofs and executing
//! distributed generic OPRF computations.

use std::{io::Read, path::Path};

use ark_bn254::Bn254;
use ark_groth16::Proof;
use eyre::Context;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use serde::Serialize;

use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
    types::ShareEpoch,
};

use world_id_primitives::{
    FieldElement, OprfPrefix, OprfPrefixedFieldElement, ProofRequest, ProofType, TREE_DEPTH,
    billing::{BILLED_ACTION_PREFIX, BillingContext, BillingWitness},
    oprf::{
        CredentialBlindingFactorOprfRequestAuthV1, NullifierOprfRequestAuthV1, OprfModule,
        RpSignatureVerification,
    },
};

use crate::circuit_inputs::QueryProofCircuitInput;

use crate::{AuthenticatorProofInput, ProofError, nullifier_proof::errors};
use world_id_primitives::poseidon::ds;

#[expect(unused_imports, reason = "used for docs")]
use world_id_primitives::SessionNullifier;

/// The SHA-256 fingerprint of the `OPRFQuery` `ZKey`.
pub const QUERY_ZKEY_FINGERPRINT: &str =
    "616c98c6ba024b5a4015d3ebfd20f6cab12e1e33486080c5167a4bcfac111798";
/// The SHA-256 fingerprint of the `OPRFQuery` witness graph.
pub const QUERY_GRAPH_FINGERPRINT: &str =
    "6b0cb90304c510f9142a555fe2b7cf31b9f68f6f37286f4471fd5d03e91da311";

/// Loads the [`CircomGroth16Material`] for the query proof from the provided reader.
///
/// # Errors
/// Will return an error if the material cannot be loaded or verified.
pub fn load_query_material_from_reader(
    zkey: impl Read,
    graph: impl Read,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_query_builder().build_from_reader(zkey, graph)?)
}

/// Loads the [`CircomGroth16Material`] for the query proof from the provided paths.
///
/// # Errors
/// Will return an error if the material cannot be loaded or verified.
pub fn load_query_material_from_paths(
    zkey: impl AsRef<Path>,
    graph: impl AsRef<Path>,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_query_builder().build_from_paths(zkey, graph)?)
}

fn build_query_builder() -> CircomGroth16MaterialBuilder {
    CircomGroth16MaterialBuilder::new()
        .fingerprint_zkey(QUERY_ZKEY_FINGERPRINT.into())
        .fingerprint_graph(QUERY_GRAPH_FINGERPRINT.into())
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
}

/// The main entry point to execute OPRF computations using the
/// OPRF nodes.
pub struct OprfEntrypoint<'a> {
    /// The list of endpoints of all OPRF nodes.
    services: &'a [String],
    /// The minimum number of OPRF nodes responses required to compute a valid nullifier. The
    /// source of truth for this value lives in the `OprfKeyRegistry` contract.
    threshold: usize,
    /// The material for the query proof circuit.
    query_material: &'a CircomGroth16Material,
    /// See [`AuthenticatorProofInput`] for more details. This is owned to zeroize signing key after use.
    authenticator_input: AuthenticatorProofInput,
    /// The network connector to make requests.
    connector: &'a Connector,
}

/// A complete verifiable OPRF output with the entire inputs to the Query Proof circuit.
#[derive(Debug, Clone)]
pub struct FullOprfOutput {
    /// The raw inputs to the Query Proof circuit
    pub query_proof_input: QueryProofCircuitInput<TREE_DEPTH>,
    /// The result of the distributed OPRF protocol.
    pub verifiable_oprf_output: VerifiableOprfOutput,
}

impl FullOprfOutput {
    /// Returns the final OPRF output as a field element.
    ///
    /// This may represent a nullifier, a credential blinding factor, etc.
    #[must_use]
    pub fn oprf_output(&self) -> FieldElement {
        self.verifiable_oprf_output.output.into()
    }

    /// The values a Proof of Embedding Similarity needs from a billing query (WIP-107 §4.6), for
    /// an output of [`OprfEntrypoint::gen_billing_nullifier`].
    #[must_use]
    pub fn billing_witness(&self) -> BillingWitness {
        let response = self.verifiable_oprf_output.unblinded_response;
        BillingWitness {
            billing_action: self.query_proof_input.action.into(),
            billing_nullifier: self.oprf_output(),
            billing_oprf_output: [response.x.into(), response.y.into()],
        }
    }
}

impl<'a> OprfEntrypoint<'a> {
    pub fn new(
        services: &'a [String],
        threshold: usize,
        query_material: &'a CircomGroth16Material,
        authenticator_input: AuthenticatorProofInput,
        connector: &'a Connector,
    ) -> Self {
        Self {
            services,
            threshold,
            query_material,
            authenticator_input,
            connector,
        }
    }

    /// Generates a blinding factor for a Credential's `sub` through the OPRF nodes.
    ///
    /// This method will handle the signature from the Authenticator authorizing the
    /// request for the OPRF nodes.
    ///
    /// # Arguments
    /// - `issuer_schema_id`: The schema ID of the credential issuer for which the blinding factor
    ///   is being generated.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] in the following cases:
    /// * `PublicKeyNotFound` - the public key for the given authenticator private key is not found in the `key_set`.
    /// * `InvalidDLogProof` – the `DLog` equality proof could not be verified.
    /// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
    pub async fn gen_credential_blinding_factor<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        issuer_schema_id: u64,
    ) -> Result<(FieldElement, ShareEpoch), ProofError> {
        // Currently, the `action` (i.e. query) is always zero, this may change in future
        let action = FieldElement::ZERO;

        let result = Self::generate_query_proof(
            self.query_material,
            &self.authenticator_input,
            action,
            FieldElement::ZERO,
            issuer_schema_id.into(),
            rng,
        )?;

        let auth = CredentialBlindingFactorOprfRequestAuthV1 {
            proof: result.proof.into(),
            action: *action,
            nonce: *FieldElement::ZERO,
            merkle_root: *self.authenticator_input.inclusion_proof.root,
            issuer_schema_id,
        };

        let verifiable_oprf_output = Self::execute_distributed_oprf(
            self.services,
            self.threshold,
            result.query_hash,
            result.blinding_factor,
            auth,
            OprfModule::CredentialBlindingFactor,
            self.connector.clone(),
        )
        .await?;
        Ok((
            verifiable_oprf_output.output.into(),
            verifiable_oprf_output.epoch,
        ))
    }

    /// Generates a nullifier through the provided OPRF nodes for
    /// a specific proof request.
    ///
    /// # Arguments
    /// - `rng`: cryptographically secure randomness for generating the query proof.
    /// - `proof_request`: the request to authenticate and fulfill.
    /// - `now`: the caller-supplied current Unix timestamp, used to reject expired requests.
    ///
    /// # Note on Session Proofs
    /// A randomized action is required on Session Proofs to ensure the output nullifier from the Uniqueness Proof
    /// circuit is unique (otherwise the one-time use property of nullifiers would fail). Please see the "Future"
    /// section in the [`SessionNullifier`] documentation for more details on how this is expected to be deprecated with
    /// a future update.
    ///
    /// # Errors
    /// Returns [`ProofError`] in the following cases:
    /// * `PublicKeyNotFound` - the public key for the given authenticator private key is not found in the `key_set`.
    /// * `InvalidDLogProof` – the `DLog` equality proof could not be verified.
    /// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
    pub async fn gen_nullifier<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        proof_request: &ProofRequest,
        now: u64,
    ) -> Result<FullOprfOutput, ProofError> {
        proof_request
            .validate_proof_type()
            .map_err(|err| ProofError::GenerationError(err.to_string()))?;

        let (action, module) = match proof_request.proof_type {
            // For session proofs a random action is used internally. This is opaque to RPs who receive
            // it within the encoded `SessionNullifier`
            ProofType::Session => (
                FieldElement::random_with_prefix(rng, OprfPrefix::SessionAction),
                OprfModule::Session,
            ),
            ProofType::Uniqueness { action } => (action, OprfModule::Nullifier),
            ProofType::EmbeddingSimilarity(_) => {
                return Err(ProofError::GenerationError(
                    "embedding similarity proofs have no nullifier query".to_string(),
                ));
            }
        };

        // Quick validation before performing the compute-heavy `generate_query_proof` fn.
        validate_proof_request_timestamps(proof_request.created_at, proof_request.expires_at, now)?;

        let result = Self::generate_query_proof(
            self.query_material,
            &self.authenticator_input,
            action,
            proof_request.nonce,
            proof_request.rp_id.into(),
            rng,
        )?;

        let auth = NullifierOprfRequestAuthV1 {
            proof: result.proof.into(),
            action: *action,
            nonce: *proof_request.nonce,
            merkle_root: *self.authenticator_input.inclusion_proof.root,
            created_at: proof_request.created_at,
            expires_at: proof_request.expires_at,
            signature: Some(proof_request.signature),
            rp_id: proof_request.rp_id,
            wip101_data: None,
            rp_signature_verification: None,
        };

        let verifiable_oprf_output = Self::execute_distributed_oprf(
            self.services,
            self.threshold,
            result.query_hash,
            result.blinding_factor,
            auth,
            module,
            self.connector.clone(),
        )
        .await?;

        Ok(FullOprfOutput {
            query_proof_input: result.query_proof_input,
            verifiable_oprf_output,
        })
    }

    /// Generates the billing nullifier of `scope` for a Proof of Embedding Similarity request
    /// through the OPRF nodes (WIP-107 §4.5).
    ///
    /// The query's action is the `billingAction` of `scope`. It carries the request's signed action
    /// and `scope` so that the nodes can check the RP authorized it. The output's
    /// [`FullOprfOutput::oprf_output`] is the `billingNullifier`; the output also feeds the
    /// registration proof and [`FullOprfOutput::billing_witness`].
    ///
    /// # Errors
    /// Returns [`ProofError::GenerationError`] if `proof_request` is not a valid Proof of
    /// Embedding Similarity request, or `scope` is for another RP or not active at `now`, and
    /// [`ProofError::ProofInputError`] if the request has expired. Other errors propagate from the
    /// query proof and the OPRF nodes.
    pub async fn gen_billing_nullifier<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        proof_request: &ProofRequest,
        scope: &BillingContext,
        now: u64,
    ) -> Result<FullOprfOutput, ProofError> {
        let signed_action = validate_billing_query(proof_request, scope, now)?;
        let billing_action = scope.billing_action();

        let result = Self::generate_query_proof(
            self.query_material,
            &self.authenticator_input,
            billing_action,
            proof_request.nonce,
            proof_request.rp_id.into(),
            rng,
        )?;

        let auth = NullifierOprfRequestAuthV1 {
            proof: result.proof.into(),
            action: *billing_action,
            nonce: *proof_request.nonce,
            merkle_root: *self.authenticator_input.inclusion_proof.root,
            created_at: proof_request.created_at,
            expires_at: proof_request.expires_at,
            signature: Some(proof_request.signature),
            rp_id: proof_request.rp_id,
            wip101_data: None,
            rp_signature_verification: Some(RpSignatureVerification::Billing {
                action: signed_action,
                scope: *scope,
            }),
        };

        let verifiable_oprf_output = Self::execute_distributed_oprf(
            self.services,
            self.threshold,
            result.query_hash,
            result.blinding_factor,
            auth,
            OprfModule::Nullifier,
            self.connector.clone(),
        )
        .await?;

        Ok(FullOprfOutput {
            query_proof_input: result.query_proof_input,
            verifiable_oprf_output,
        })
    }

    pub async fn derive_session_id_r_seed<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        proof_request: &ProofRequest,
        oprf_seed: FieldElement,
    ) -> Result<FullOprfOutput, ProofError> {
        proof_request
            .validate_proof_type()
            .map_err(|err| ProofError::GenerationError(err.to_string()))?;
        if proof_request.session_id.is_none() {
            return Err(ProofError::GenerationError(
                "session randomness can only be derived for requests with a \"create\" or existing session_id".to_string(),
            ));
        }

        let result = Self::generate_query_proof(
            self.query_material,
            &self.authenticator_input,
            oprf_seed,
            proof_request.nonce,
            proof_request.rp_id.into(),
            rng,
        )?;

        let rp_signature_verification = match &proof_request.proof_type {
            ProofType::Uniqueness { action } => {
                Some(RpSignatureVerification::UniquenessAction { action: *action })
            }
            ProofType::EmbeddingSimilarity(params) => {
                Some(RpSignatureVerification::EmbeddingSimilarityAction {
                    action: params.action,
                })
            }
            ProofType::Session => None,
        };

        let auth = NullifierOprfRequestAuthV1 {
            proof: result.proof.into(),
            action: *oprf_seed,
            nonce: *proof_request.nonce,
            merkle_root: *self.authenticator_input.inclusion_proof.root,
            created_at: proof_request.created_at,
            expires_at: proof_request.expires_at,
            signature: Some(proof_request.signature),
            rp_id: proof_request.rp_id,
            wip101_data: None,
            rp_signature_verification,
        };

        let verifiable_oprf_output = Self::execute_distributed_oprf(
            self.services,
            self.threshold,
            result.query_hash,
            result.blinding_factor,
            auth,
            OprfModule::Session,
            self.connector.clone(),
        )
        .await?;

        Ok(FullOprfOutput {
            query_proof_input: result.query_proof_input,
            verifiable_oprf_output,
        })
    }
}

/// Checks a billing query before the compute-heavy query proof and returns the request's signed
/// action: the request is a valid Proof of Embedding Similarity request whose action carries
/// [`BILLED_ACTION_PREFIX`], it has not expired, and `scope` is for its RP and active at `now`.
fn validate_billing_query(
    proof_request: &ProofRequest,
    scope: &BillingContext,
    now: u64,
) -> Result<FieldElement, ProofError> {
    proof_request
        .validate_proof_type()
        .map_err(|err| ProofError::GenerationError(err.to_string()))?;
    let ProofType::EmbeddingSimilarity(params) = &proof_request.proof_type else {
        return Err(ProofError::GenerationError(
            "billing queries are only made for embedding similarity requests".to_string(),
        ));
    };
    // `validate_proof_type` checks the prefix too; this keeps the invariant local.
    if !params.action.has_prefix(BILLED_ACTION_PREFIX) {
        return Err(ProofError::GenerationError(
            "the request's action must carry the billed action prefix".to_string(),
        ));
    }
    if scope.rp_id != proof_request.rp_id {
        return Err(ProofError::GenerationError(
            "the billing context is for another RP".to_string(),
        ));
    }
    if !scope.is_active_at(now) {
        return Err(ProofError::GenerationError(
            "the billing context is not a canonical period active now".to_string(),
        ));
    }
    validate_proof_request_timestamps(proof_request.created_at, proof_request.expires_at, now)?;
    Ok(params.action)
}

fn validate_proof_request_timestamps(
    created_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), ProofError> {
    if created_at > expires_at {
        return Err(ProofError::ProofInputError(
            errors::ProofInputError::InvalidExpiresAt {
                created_at,
                expires_at,
            },
        ));
    }
    if now > expires_at {
        return Err(ProofError::ProofInputError(
            errors::ProofInputError::ProofRequestExpired {
                current_timestamp: now,
                expires_at,
            },
        ));
    }
    Ok(())
}

impl<'a> OprfEntrypoint<'a> {
    /// Generates a query proof: creates a blinding factor, computes
    /// the query hash, signs it, builds [`QueryProofCircuitInput`], and
    /// runs Groth16 prove + verify.
    fn generate_query_proof<R: rand::CryptoRng + rand::RngCore>(
        query_material: &CircomGroth16Material,
        authenticator_input: &AuthenticatorProofInput,
        action: FieldElement,
        nonce: FieldElement,
        scope: FieldElement,
        rng: &mut R,
    ) -> Result<QueryProofResult, ProofError> {
        let blinding_factor = BlindingFactor::rand(rng);

        let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
            authenticator_input.inclusion_proof.siblings.map(|s| *s);

        let query_hash = world_id_primitives::authenticator::oprf_query_digest(
            authenticator_input.inclusion_proof.leaf_index,
            action,
            scope,
        );
        let signature = authenticator_input.private_key.sign(*query_hash);

        let query_proof_input = QueryProofCircuitInput::<TREE_DEPTH> {
            pk: authenticator_input.key_set.as_affine_array(),
            pk_index: authenticator_input.key_index.into(),
            s: signature.s,
            r: signature.r,
            merkle_root: *authenticator_input.inclusion_proof.root,
            depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            mt_index: authenticator_input.inclusion_proof.leaf_index.into(),
            siblings,
            beta: blinding_factor.beta(),
            rp_id: *scope,
            action: *action,
            nonce: *nonce,
        };
        let _ = errors::check_query_input_validity(&query_proof_input)?;

        tracing::debug!("generating query proof");
        let (proof, public_inputs) = query_material.generate_proof(&query_proof_input, rng)?;
        query_material.verify_proof(&proof, &public_inputs)?;
        tracing::debug!("generated query proof");

        Ok(QueryProofResult {
            query_proof_input,
            proof,
            query_hash: *query_hash,
            blinding_factor,
        })
    }

    /// Executes the distributed OPRF protocol against the given
    /// service endpoints.
    async fn execute_distributed_oprf<A: Clone + Serialize + Send + 'static>(
        services: &[String],
        threshold: usize,
        query_hash: ark_babyjubjub::Fq,
        blinding_factor: BlindingFactor,
        auth: A,
        oprf_module: OprfModule,
        connector: Connector,
    ) -> Result<VerifiableOprfOutput, ProofError> {
        tracing::debug!("executing distributed OPRF");

        let service_uris = taceo_oprf::client::to_oprf_uri_many(services, oprf_module)
            .context("while building service URI")?;

        let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
            &service_uris,
            threshold,
            query_hash,
            blinding_factor,
            *ds::OPRF_PROOF.as_field_element(),
            auth,
            connector,
        )
        .await?;

        Ok(verifiable_oprf_output)
    }
}

/// Intermediate result from query proof generation.
struct QueryProofResult {
    query_proof_input: QueryProofCircuitInput<TREE_DEPTH>,
    proof: Proof<Bn254>,
    query_hash: ark_babyjubjub::Fq,
    blinding_factor: BlindingFactor,
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(100, 200, 150 => matches Ok(()); "valid")]
    #[test_case(201, 200, 150 => matches Err(ProofError::ProofInputError(
        errors::ProofInputError::InvalidExpiresAt { created_at: 201, expires_at: 200 }
    )); "created after expiration")]
    #[test_case(100, 200, 201 => matches Err(ProofError::ProofInputError(
        errors::ProofInputError::ProofRequestExpired { current_timestamp: 201, expires_at: 200 }
    )); "expired at caller time")]
    fn proof_request_timestamp_validation(
        created_at: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<(), ProofError> {
        validate_proof_request_timestamps(created_at, expires_at, now)
    }

    mod billing {
        use super::*;
        use alloy_primitives::{Address, U256};
        use world_id_primitives::{
            EmbeddingSimilarityParams, FlamingoConfiguration, RequestItem, SessionRef,
            request::RequestVersion, rp::RpId,
        };

        /// Midnight Anywhere on Earth on 1 November 2026, a canonical period start.
        const NOVEMBER_2026: u64 = 1_793_534_400;
        const NOW: u64 = NOVEMBER_2026 + 600;

        fn prefixed(prefix: OprfPrefix) -> FieldElement {
            let mut bytes = [0x22u8; 32];
            bytes[0] = prefix as u8;
            FieldElement::from_be_bytes(&bytes).expect("in field")
        }

        fn request() -> ProofRequest {
            ProofRequest {
                id: "req".into(),
                version: RequestVersion::V1,
                proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
                    action: prefixed(OprfPrefix::EmbeddingSimilarity),
                    challenge_hash: FieldElement::from(7u64),
                    flamingo_configurations: vec![FlamingoConfiguration {
                        iss: "https://engine.example".into(),
                        pipeline_id: 1,
                        match_strictness: 1,
                        min_version: 1,
                    }],
                    aat: None,
                }),
                created_at: NOW - 60,
                expires_at: NOW + 240,
                rp_id: RpId::new(42),
                oprf_key_id: taceo_oprf::types::OprfKeyId::new(ruint::uint!(9_U160)),
                session_id: SessionRef::None,
                signature: alloy_primitives::Signature::new(
                    U256::from(1u64),
                    U256::from(2u64),
                    true,
                ),
                nonce: FieldElement::from(5u64),
                requests: vec![RequestItem::new("poh".into(), 1, None, None, None)],
                constraints: None,
            }
        }

        fn scope(period_start: u64) -> BillingContext {
            BillingContext {
                chain_id: U256::from(480u64),
                billing_contract: Address::repeat_byte(0xb1),
                rp_id: RpId::new(42),
                period_start,
            }
        }

        fn rejection(result: Result<FieldElement, ProofError>) -> String {
            match result {
                Err(ProofError::GenerationError(reason)) => reason,
                other => panic!("expected a generation error, got {other:?}"),
            }
        }

        #[test]
        fn accepts_an_embedding_similarity_request_for_an_active_period() {
            let signed = validate_billing_query(&request(), &scope(NOVEMBER_2026), NOW)
                .expect("valid billing query");
            assert_eq!(signed, prefixed(OprfPrefix::EmbeddingSimilarity));
        }

        #[test]
        fn rejects_other_proof_types() {
            let mut request = request();
            request.proof_type = ProofType::Uniqueness {
                action: prefixed(OprfPrefix::Uniqueness),
            };
            assert!(
                rejection(validate_billing_query(&request, &scope(NOVEMBER_2026), NOW))
                    .contains("embedding similarity")
            );
        }

        #[test]
        fn rejects_another_rp() {
            let mut scope = scope(NOVEMBER_2026);
            scope.rp_id = RpId::new(43);
            assert!(
                rejection(validate_billing_query(&request(), &scope, NOW)).contains("another RP")
            );
        }

        #[test]
        fn rejects_an_inactive_or_noncanonical_period() {
            for period_start in [NOVEMBER_2026 + 1, NOVEMBER_2026 + 31 * 24 * 60 * 60] {
                assert!(
                    rejection(validate_billing_query(
                        &request(),
                        &scope(period_start),
                        NOW
                    ))
                    .contains("not a canonical period active now")
                );
            }
        }

        #[test]
        fn rejects_an_expired_request() {
            let request = request();
            assert!(matches!(
                validate_billing_query(&request, &scope(NOVEMBER_2026), request.expires_at + 1),
                Err(ProofError::ProofInputError(
                    errors::ProofInputError::ProofRequestExpired { .. }
                ))
            ));
        }
    }
}
