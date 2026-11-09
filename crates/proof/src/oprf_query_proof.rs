//! Shared helpers for generating query proofs and executing
//! distributed generic OPRF computations.

use std::{io::Read, path::Path};

use ark_bn254::Bn254;
use ark_groth16::Proof;
use eddsa_babyjubjub::EdDSAPublicKey;
use eyre::Context;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use serde::Serialize;

use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
    types::ShareEpoch,
};

use world_id_primitives::{
    AuthenticatorPublicKeySet, FieldElement, MAX_AUTHENTICATOR_KEYS, OprfPrefix,
    OprfPrefixedFieldElement, ProofRequest, ProofType, TREE_DEPTH,
    billing::{BILLED_ACTION_PREFIX, BillingContext, BillingWitness},
    merkle::MerkleInclusionProof,
    oprf::{
        CredentialBlindingFactorOprfRequestAuthV1, NullifierOprfRequestAuthV1, OprfModule,
        RpSignatureVerification,
    },
};

use crate::circuit_inputs::QueryProofCircuitInput;

use crate::{
    AuthenticatorProofInput, ProofError, ProofInputError, groth16::groth16_material_builder,
};
use world_id_primitives::poseidon::ds;

type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;

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
    groth16_material_builder(QUERY_ZKEY_FINGERPRINT, QUERY_GRAPH_FINGERPRINT)
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
            ProofInputError::InvalidExpiresAt {
                created_at,
                expires_at,
            },
        ));
    }
    if now > expires_at {
        return Err(ProofError::ProofInputError(
            ProofInputError::ProofRequestExpired {
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
        let _ = check_query_input_validity(&query_proof_input)?;

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

// ============================================================================
// Input Check
// ============================================================================

/// This method checks the validity of the input parameters by emulating the operations that are proved in ZK and raising Errors that would result in an invalid proof.
///
/// Returns the blinded OPRF query point if everything is ok.
///
/// # Errors
/// This function will return a [`ProofInputError`] if any of the checks fail.
/// The `Display` implementation of this error can be used to get a human-readable error message on which parts of the input were invalid.
pub fn check_query_input_validity<const TREE_DEPTH: usize>(
    inputs: &QueryProofCircuitInput<TREE_DEPTH>,
) -> Result<Affine, ProofInputError> {
    // 1. Check that the depth is within bounds.
    if inputs.depth != BaseField::new((TREE_DEPTH as u64).into()) {
        return Err(ProofInputError::InvalidMerkleTreeDepth {
            expected: TREE_DEPTH,
            is: inputs.depth,
        });
    }
    // 2. Check the merkle proof is valid
    // Check the Merkle tree idx is valid.
    let idx_u64 = u64::try_from(FieldElement::from(inputs.mt_index)).map_err(|_| {
        ProofInputError::ValueOutOfBounds {
            name: "Merkle tree index",
            is: inputs.mt_index,
            limit: BaseField::new((1u64 << TREE_DEPTH).into()),
        }
    })?;
    if idx_u64 >= (1u64 << TREE_DEPTH) {
        return Err(ProofInputError::ValueOutOfBounds {
            name: "Merkle tree index",
            is: inputs.mt_index,
            limit: BaseField::new((1u64 << TREE_DEPTH).into()),
        });
    }

    // Build the leaf from the PKs.
    let pk_set = AuthenticatorPublicKeySet::new(
        inputs
            .pk
            .iter()
            .map(|&x| EdDSAPublicKey { pk: x })
            .collect(),
    )
    .map_err(|_| ProofInputError::InvalidAuthenticatorPublicKeySet)?;
    let pk_set_hash = pk_set.leaf_hash();
    let merkle_tree_inclusion_proof = MerkleInclusionProof::new(
        FieldElement::from(inputs.merkle_root),
        idx_u64,
        inputs.siblings.map(FieldElement::from),
    );
    if !merkle_tree_inclusion_proof.is_valid(FieldElement::from(pk_set_hash)) {
        return Err(ProofInputError::InvalidMerkleTreeInclusionProof);
    }

    // 3. Check that the signature is valid.
    let pk_index_usize = usize::try_from(FieldElement::from(inputs.pk_index)).map_err(|_| {
        ProofInputError::ValueOutOfBounds {
            name: "Authenticator PubKey index",
            is: inputs.pk_index,
            limit: BaseField::new((MAX_AUTHENTICATOR_KEYS as u64).into()),
        }
    })?;
    let pk = pk_set
        .get(pk_index_usize)
        .ok_or_else(|| ProofInputError::ValueOutOfBounds {
            name: "Authenticator PubKey index",
            is: inputs.pk_index,
            limit: BaseField::new((MAX_AUTHENTICATOR_KEYS as u64).into()),
        })?;

    if !inputs.r.is_on_curve() || !inputs.r.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ProofInputError::InvalidBabyJubJubPoint {
            name: "Query Signature R",
        });
    }
    if !pk.pk.is_on_curve() || !pk.pk.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ProofInputError::InvalidBabyJubJubPoint {
            name: "Authenticator Public Key",
        });
    }

    let _rp_id_u64 = u64::try_from(FieldElement::from(inputs.rp_id)).map_err(|_| {
        ProofInputError::ValueOutOfBounds {
            name: "RP Id",
            is: inputs.rp_id,
            limit: BaseField::new(u64::MAX.into()),
        }
    })?;
    let query = world_id_primitives::authenticator::oprf_query_digest(
        idx_u64,
        FieldElement::from(inputs.action),
        FieldElement::from(inputs.rp_id),
    );
    let signature = eddsa_babyjubjub::EdDSASignature {
        r: inputs.r,
        s: inputs.s,
    };

    if !pk.verify(*query, &signature) {
        return Err(ProofInputError::InvalidAuthenticatorSignature);
    }

    let blinding_factor = BlindingFactor::from_scalar(inputs.beta)
        .map_err(|_| ProofInputError::InvalidBlindingFactor)?;
    let query_point = taceo_oprf::core::oprf::client::blind_query(*query, blinding_factor);

    Ok(query_point.blinded_query())
}

#[cfg(test)]
pub(crate) mod input_validation_tests {
    use std::str::FromStr;

    use ark_ec::twisted_edwards::Affine;

    use world_id_primitives::poseidon;

    use super::check_query_input_validity;
    use crate::circuit_inputs::QueryProofCircuitInput;

    // gotten these values by `dbg`-ing the struct in the e2e_authenticator_generate test
    pub(crate) fn get_valid_query_proof_input() -> QueryProofCircuitInput<30> {
        QueryProofCircuitInput {
            pk: [Affine {
                x: ark_babyjubjub::Fq::from_str(
                    "19037598474602150174935475944965340829216795940473064039209388058233204431288",
                ).unwrap(),
                y: ark_babyjubjub::Fq::from_str(
                    "3549932221586364715003722955756497910920276078443163728621283280434115857197",
                ).unwrap(),
            },
                Affine::zero(),
                Affine::zero(),
                Affine::zero(),
                Affine::zero(),
                Affine::zero(),
                Affine::zero(),
            ],
            pk_index: ark_bn254::Fr::from(0u64),
            s: ark_babyjubjub::Fr::from_str(
                "2692248185200295468055279425612708965310378163906753799023551825366269352327",
            ).unwrap(),
            r: Affine {
               x: ark_babyjubjub::Fq::from_str(
                    "14689596469778385278298478829656243946283084496217945909620117398922933730711",
                ).unwrap(),
                y: ark_babyjubjub::Fq::from_str(
                    "4424830738973486800075394160997493242162871494907432163152597205147606706197",
                ).unwrap(),
            },
            merkle_root: ark_bn254::Fr::from_str("4959814736111706042728533661656003495359474679272202023690954858781105690707").unwrap(),
            depth: ark_babyjubjub::Fq::from(30u64),
            mt_index: ark_bn254::Fr::from(1u64),
            siblings: [
                    ark_bn254::Fr::from_str("0").unwrap(),
                    ark_bn254::Fr::from_str("15621590199821056450610068202457788725601603091791048810523422053872049975191").unwrap(),
                    ark_bn254::Fr::from_str("15180302612178352054084191513289999058431498575847349863917170755410077436260").unwrap(),
                    ark_bn254::Fr::from_str("20846426933296943402289409165716903143674406371782261099735847433924593192150").unwrap(),
                    ark_bn254::Fr::from_str("19570709311100149041770094415303300085749902031216638721752284824736726831172").unwrap(),
                    ark_bn254::Fr::from_str("11737142173000203701607979434185548337265641794352013537668027209469132654026").unwrap(),
                    ark_bn254::Fr::from_str("11865865012735342650993929214218361747705569437250152833912362711743119784159").unwrap(),
                    ark_bn254::Fr::from_str("1493463551715988755902230605042557878234810673525086316376178495918903796315").unwrap(),
                    ark_bn254::Fr::from_str("18746103596419850001763894956142528089435746267438407061601783590659355049966").unwrap(),
                    ark_bn254::Fr::from_str("21234194473503024590374857258930930634542887619436018385581872843343250130100").unwrap(),
                    ark_bn254::Fr::from_str("14681119568252857310414189897145410009875739166689283501408363922419813627484").unwrap(),
                    ark_bn254::Fr::from_str("13243470632183094581890559006623686685113540193867211988709619438324105679244").unwrap(),
                    ark_bn254::Fr::from_str("19463898140191333844443019106944343282402694318119383727674782613189581590092").unwrap(),
                    ark_bn254::Fr::from_str("10565902370220049529800497209344287504121041033501189980624875736992201671117").unwrap(),
                    ark_bn254::Fr::from_str("5560307625408070902174028041423028597194394554482880015024167821933869023078").unwrap(),
                    ark_bn254::Fr::from_str("20576730574720116265513866548855226316241518026808984067485384181494744706390").unwrap(),
                    ark_bn254::Fr::from_str("11166760821615661136366651998133963805984915741187325490784169611245269155689").unwrap(),
                    ark_bn254::Fr::from_str("13692603500396323648417392244466291089928913430742736835590182936663435788822").unwrap(),
                    ark_bn254::Fr::from_str("11129674755567463025028188404867541558752927519269975708924528737249823830641").unwrap(),
                    ark_bn254::Fr::from_str("6673535049007525806710184801639542254440636510496168661971704157154828514023").unwrap(),
                    ark_bn254::Fr::from_str("7958154589163466663626421142270206662020519181323839780192984613274682930816").unwrap(),
                    ark_bn254::Fr::from_str("3739156991379607404516753076057250171966250101655747790592556040569841550790").unwrap(),
                    ark_bn254::Fr::from_str("1334107297020502384420211493664486465203492095766400031330900935069700302301").unwrap(),
                    ark_bn254::Fr::from_str("20357028769054354174264046872903423695314313082869184437966002491602414517674").unwrap(),
                    ark_bn254::Fr::from_str("19392290367394672558538719012722289280213395590510602524366987685302929990731").unwrap(),
                    ark_bn254::Fr::from_str("7360502715619830055199267117332475946442427205382059394111067387016428818088").unwrap(),
                    ark_bn254::Fr::from_str("9629177338475347225553791169746168712988898028547587350296027054067573957412").unwrap(),
                    ark_bn254::Fr::from_str("21877160135037839571797468541807904053886800340144060811298025652177410263004").unwrap(),
                    ark_bn254::Fr::from_str("7105691694342706282901391345307729036900705570482804586768449537652208350743").unwrap(),
                    ark_bn254::Fr::from_str("15888057581779748293164452094398990053773731478520540058125130669204703869637").unwrap(),
            ],
            beta: ark_babyjubjub::Fr::from_str("1277277022932719396321614946989807194659268059729440522321681213750340643042").unwrap(),
            rp_id: ark_bn254::Fr::from_str("14631649082411674499").unwrap(),
            action: ark_bn254::Fr::from_str("8982441576518976929447725179565370305223105654688049122733783421407497941726").unwrap(),
            nonce: ark_bn254::Fr::from_str("8530676162050357218814694371816107906694725175836943927290214963954696613748").unwrap(),
        }
    }

    #[test]
    fn test_valid_query_proof_input() {
        let inputs = get_valid_query_proof_input();
        let _ = check_query_input_validity(&inputs).unwrap();
    }

    #[test]
    fn test_invalid_query_proof_input() {
        let inputs = get_valid_query_proof_input();
        {
            let mut inputs = inputs.clone();
            inputs.depth = ark_babyjubjub::Fq::from(29u64); // invalid depth
            assert!(matches!(
                check_query_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidMerkleTreeDepth { .. }
            ));
        }
        {
            let mut inputs = inputs.clone();
            // 1 << 30
            inputs.mt_index = ark_bn254::Fr::from(1073741824u64);
            assert!(matches!(
                check_query_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::ValueOutOfBounds {
                    name: "Merkle tree index",
                    ..
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.merkle_root = ark_bn254::Fr::from(12345u64);
            assert!(matches!(
                check_query_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidMerkleTreeInclusionProof
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.pk_index = ark_bn254::Fr::from(7u64); // MAX_AUTHENTICATOR_KEYS is 7, so index 7 is out of bounds (0-6)
            assert!(matches!(
                check_query_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::ValueOutOfBounds {
                    name: "Authenticator PubKey index",
                    ..
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.r = Affine {
                x: ark_babyjubjub::Fq::from(1u64),
                y: ark_babyjubjub::Fq::from(2u64),
            };
            assert!(matches!(
                check_query_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidBabyJubJubPoint {
                    name: "Query Signature R"
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.pk[0] = Affine {
                x: ark_babyjubjub::Fq::from(1u64),
                y: ark_babyjubjub::Fq::from(2u64),
            };

            // Recompute the merkle root so the proof is valid
            let pk_set = world_id_primitives::AuthenticatorPublicKeySet::new(
                inputs
                    .pk
                    .iter()
                    .map(|&x| eddsa_babyjubjub::EdDSAPublicKey { pk: x })
                    .collect(),
            )
            .unwrap();
            let mut current = pk_set.leaf_hash();
            let idx =
                u64::try_from(world_id_primitives::FieldElement::from(inputs.mt_index)).unwrap();
            for (i, sibling) in inputs.siblings.iter().enumerate() {
                let sibling_fr = *world_id_primitives::FieldElement::from(*sibling);
                current = if (idx >> i) & 1 == 0 {
                    *poseidon::compress(current.into(), sibling_fr.into())
                } else {
                    *poseidon::compress(sibling_fr.into(), current.into())
                };
            }
            inputs.merkle_root = current;

            assert!(matches!(
                check_query_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidBabyJubJubPoint {
                    name: "Authenticator Public Key"
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.action = ark_bn254::Fr::from(12345u64);
            assert!(matches!(
                check_query_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidAuthenticatorSignature
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(100, 200, 150 => matches Ok(()); "valid")]
    #[test_case(201, 200, 150 => matches Err(ProofError::ProofInputError(
        ProofInputError::InvalidExpiresAt { created_at: 201, expires_at: 200 }
    )); "created after expiration")]
    #[test_case(100, 200, 201 => matches Err(ProofError::ProofInputError(
        ProofInputError::ProofRequestExpired { current_timestamp: 201, expires_at: 200 }
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
            EmbeddingSimilarityParams, RequestItem, SessionRef, request::RequestVersion, rp::RpId,
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
                    ProofInputError::ProofRequestExpired { .. }
                ))
            ));
        }
    }
}
