//! Shared helpers for generating query proofs and executing
//! distributed generic OPRF computations.

use ark_bn254::Bn254;
use ark_ff::PrimeField;
use ark_groth16::Proof;
use eyre::Context;
use groth16_material::circom::CircomGroth16Material;
use serde::Serialize;

use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
    types::ShareEpoch,
};

use world_id_primitives::{
    FieldElement, ProofRequest, SessionFeType, SessionFieldElement, TREE_DEPTH,
    circuit_inputs::QueryProofCircuitInput,
    oprf::{CredentialBlindingFactorOprfRequestAuthV1, NullifierOprfRequestAuthV1, OprfModule},
};

use crate::{
    AuthenticatorProofInput,
    proof::{OPRF_PROOF_DS, ProofError, errors},
};

#[expect(unused_imports, reason = "used for docs")]
use world_id_primitives::SessionNullifier;

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
    ) -> Result<FullOprfOutput, ProofError> {
        let (action, module) = if proof_request.is_session_proof() {
            // For session proofs a random action is used internally. This is opaque to RPs who receive
            // it within the encoded `SessionNullifier`
            let action = FieldElement::random_for_session(rng, SessionFeType::Action);
            (action, OprfModule::Session)
        } else {
            // If the RP didn't provide an action, we provide a default.
            let action = proof_request.action.unwrap_or(FieldElement::ZERO);
            (action, OprfModule::Nullifier)
        };

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
            current_time_stamp: proof_request.created_at,
            expiration_timestamp: proof_request.expires_at,
            signature: proof_request.signature,
            rp_id: proof_request.rp_id,
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

    pub async fn gen_session_id_r_seed<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        proof_request: &ProofRequest,
        oprf_seed: FieldElement,
    ) -> Result<FullOprfOutput, ProofError> {
        let result = Self::generate_query_proof(
            self.query_material,
            &self.authenticator_input,
            oprf_seed,
            proof_request.nonce,
            proof_request.rp_id.into(),
            rng,
        )?;

        let auth = NullifierOprfRequestAuthV1 {
            proof: result.proof.into(),
            action: *oprf_seed,
            nonce: *proof_request.nonce,
            merkle_root: *self.authenticator_input.inclusion_proof.root,
            current_time_stamp: proof_request.created_at,
            expiration_timestamp: proof_request.expires_at,
            signature: proof_request.signature,
            rp_id: proof_request.rp_id,
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

impl<'a> OprfEntrypoint<'a> {
    /// Generates a query proof: creates a blinding factor, computes
    /// the query hash, signs it, builds `QueryProofCircuitInput`, and
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
            ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_PROOF_DS),
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
