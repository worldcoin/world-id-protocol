//! Logic to generate nullifiers using the OPRF Nodes.

use ark_ff::PrimeField;
use eddsa_babyjubjub::EdDSAPrivateKey;
use groth16_material::circom::CircomGroth16Material;

use taceo_oprf_client::{BlindingFactor, Connector, VerifiableOprfOutput};

use world_id_primitives::{
    FieldElement, TREE_DEPTH, authenticator::AuthenticatorPublicKeySet,
    circuit_inputs::QueryProofCircuitInput, merkle::MerkleInclusionProof, oprf::OprfRequestAuthV1,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    proof::{OPRF_PROOF_DS, ProofError},
    requests::ProofRequest,
};

/// Inputs from the Authenticator to generate a nullifier.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatorProofInput {
    /// The set of all public keys for all the user's authenticators.
    #[zeroize(skip)]
    key_set: AuthenticatorPublicKeySet,
    /// Inclusion proof in the World ID Registry.
    #[zeroize(skip)]
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The off-chain signer key for the Authenticator.
    private_key: EdDSAPrivateKey,
    /// The index at which the authenticator key is located in the `key_set`.
    key_index: u64,
}

impl AuthenticatorProofInput {
    /// Creates a new authenticator proof input.
    #[must_use]
    pub const fn new(
        key_set: AuthenticatorPublicKeySet,
        inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
        private_key: EdDSAPrivateKey,
        key_index: u64,
    ) -> Self {
        Self {
            key_set,
            inclusion_proof,
            private_key,
            key_index,
        }
    }
}

/// Nullifier computed using OPRF Nodes.
pub struct OprfNullifier {
    /// The raw inputs to the Query Proof circuit
    pub(crate) query_proof_input: QueryProofCircuitInput<TREE_DEPTH>,
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
    /// - `threshold`: The threshold for required OPRF nodes responses.
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

        let blinding_factor = BlindingFactor::rand(&mut rng);

        let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
            authenticator_input.inclusion_proof.siblings.map(|s| *s);

        let query_hash =
            proof_request.digest_for_authenticator(authenticator_input.inclusion_proof.leaf_index);
        let signature = authenticator_input.private_key.sign(*query_hash);

        let action = *proof_request.computed_action();

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
            rp_id: *FieldElement::from(proof_request.rp_id),
            action,
            nonce: *proof_request.nonce,
        };

        tracing::debug!("generating query proof");
        let (proof, public_inputs) = query_material.generate_proof(&query_proof_input, &mut rng)?;
        query_material.verify_proof(&proof, &public_inputs)?;
        tracing::debug!("generated query proof");

        let auth = OprfRequestAuthV1 {
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

        let verifiable_oprf_output = taceo_oprf_client::distributed_oprf(
            services,
            "rp", // module for World ID RP use-case
            threshold,
            proof_request.oprf_key_id,
            proof_request.share_epoch,
            *query_hash,
            blinding_factor,
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
