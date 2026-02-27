//! Logic to generate nullifiers using the OPRF Nodes.

use ark_ff::PrimeField;
use groth16_material::circom::CircomGroth16Material;

use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
};

use world_id_primitives::{
    FieldElement, ProofRequest, TREE_DEPTH,
    circuit_inputs::QueryProofCircuitInput,
    oprf::{NullifierOprfRequestAuthV1, OprfModule},
};

use crate::{
    AuthenticatorProofInput,
    proof::{OPRF_PROOF_DS, ProofError, errors},
};

/// Nullifier computed using OPRF Nodes.
#[derive(Debug, Clone)]
pub struct OprfNullifier {
    /// The raw inputs to the Query Proof circuit
    pub query_proof_input: QueryProofCircuitInput<TREE_DEPTH>,
    /// The result of the distributed OPRF protocol, including the final nullifier.
    pub verifiable_oprf_output: VerifiableOprfOutput,
}

impl OprfNullifier {
    /// Generates a nullifier through the provided OPRF nodes for
    /// a specific proof request.
    ///
    /// This method will handle the signature from the Authenticator authorizing the
    /// request for the OPRF nodes.
    ///
    /// # Arguments
    /// - `services`: The list of endpoints of all OPRF nodes.
    /// - `threshold`: The minimum number of OPRF nodes responses required to compute a valid nullifier. The
    ///   source of truth for this value lives in the `OprfKeyRegistry` contract.
    /// - `query_material`: The material for the query proof circuit.
    /// - `authenticator_input`: See [`AuthenticatorProofInput`] for more details.
    /// - `proof_request`: The proof request provided by the RP.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] in the following cases:
    /// * `PublicKeyNotFound` - the public key for the given authenticator private key is not found in the `key_set`.
    /// * `InvalidDLogProof` – the `DLog` equality proof could not be verified.
    /// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
    pub async fn generate(
        services: &[String],
        threshold: usize,
        query_material: &CircomGroth16Material,
        authenticator_input: AuthenticatorProofInput,
        proof_request: &ProofRequest,
        connector: Connector,
    ) -> Result<Self, ProofError> {
        let mut rng = rand::rngs::OsRng;

        let query_blinding_factor = BlindingFactor::rand(&mut rng);

        let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
            authenticator_input.inclusion_proof.siblings.map(|s| *s);

        let action = *proof_request.computed_action(&mut rng);
        let query_hash = world_id_primitives::authenticator::oprf_query_digest(
            authenticator_input.inclusion_proof.leaf_index,
            action.into(),
            proof_request.rp_id.into(),
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
            beta: query_blinding_factor.beta(),
            rp_id: *FieldElement::from(proof_request.rp_id),
            action,
            nonce: *proof_request.nonce,
        };
        let _ = errors::check_query_input_validity(&query_proof_input)?;

        tracing::debug!("generating query proof");
        let (proof, public_inputs) = query_material.generate_proof(&query_proof_input, &mut rng)?;
        query_material.verify_proof(&proof, &public_inputs)?;
        tracing::debug!("generated query proof");

        let auth = NullifierOprfRequestAuthV1 {
            proof: proof.into(),
            action,
            nonce: *proof_request.nonce,
            merkle_root: *authenticator_input.inclusion_proof.root,
            current_time_stamp: proof_request.created_at,
            expiration_timestamp: proof_request.expires_at,
            signature: proof_request.signature,
            rp_id: proof_request.rp_id,
        };

        tracing::debug!("executing distributed OPRF");

        let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
            services,
            OprfModule::Nullifier.to_string().as_str(),
            threshold,
            *query_hash,
            query_blinding_factor,
            ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_PROOF_DS),
            auth,
            connector,
        )
        .await?;

        Ok(Self {
            query_proof_input,
            verifiable_oprf_output,
        })
    }
}
