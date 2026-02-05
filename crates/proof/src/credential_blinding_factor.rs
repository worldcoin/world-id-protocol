//! Logic to generate credential blinding factors using the OPRF Nodes.

use ark_ff::PrimeField;
use groth16_material::circom::CircomGroth16Material;

use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
    types::OprfKeyId,
};

use world_id_primitives::{
    FieldElement, TREE_DEPTH,
    circuit_inputs::QueryProofCircuitInput,
    oprf::{CredentialBlindingFactorOprfRequestAuthV1, OprfModule},
};

use crate::{
    AuthenticatorProofInput,
    proof::{OPRF_PROOF_DS, ProofError},
};

/// Credential blinding factor computed using OPRF Nodes.
pub struct OprfCredentialBlindingFactor {
    /// The result of the distributed OPRF protocol, including the final blinding factor.
    pub verifiable_oprf_output: VerifiableOprfOutput,
}

impl OprfCredentialBlindingFactor {
    /// Generates a blinding factor through the provided OPRF nodes.
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
    /// - `issuer_schema_id`: The schema ID of the credential issuer.
    /// - `action`: The action for which the blinding factor is being requested.
    /// - `oprf_key_id`: The OPRF key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] in the following cases:
    /// * `PublicKeyNotFound` - the public key for the given authenticator private key is not found in the `key_set`.
    /// * `InvalidDLogProof` – the `DLog` equality proof could not be verified.
    /// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
    #[expect(clippy::too_many_arguments)]
    pub async fn generate(
        services: &[String],
        threshold: usize,
        query_material: &CircomGroth16Material,
        authenticator_input: AuthenticatorProofInput,
        issuer_schema_id: u64,
        action: FieldElement,
        oprf_key_id: OprfKeyId,
        connector: Connector,
    ) -> Result<Self, ProofError> {
        let mut rng = rand::rngs::OsRng;

        // For schema issuer OPRF, the nonce is not needed.
        let nonce = FieldElement::ZERO;

        let query_blinding_factor = BlindingFactor::rand(&mut rng);

        let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
            authenticator_input.inclusion_proof.siblings.map(|s| *s);

        let query_hash = world_id_primitives::authenticator::oprf_query_digest(
            authenticator_input.inclusion_proof.leaf_index,
            action,
            issuer_schema_id.into(),
        );
        let signature = authenticator_input.private_key.sign(*query_hash);

        let query_proof_input = QueryProofCircuitInput::<TREE_DEPTH> {
            pk: authenticator_input.key_set.as_affine_array(),
            pk_index: authenticator_input.key_index.into(),
            s: signature.s,
            r: signature.r,
            merkle_root: *authenticator_input.inclusion_proof.root,
            depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            mt_index: *authenticator_input
                .inclusion_proof
                .leaf_index_as_field_element(),
            siblings,
            beta: query_blinding_factor.beta(),
            rp_id: issuer_schema_id.into(),
            action: *action,
            nonce: *nonce,
        };

        tracing::debug!("generating query proof");
        let (proof, public_inputs) = query_material.generate_proof(&query_proof_input, &mut rng)?;
        query_material.verify_proof(&proof, &public_inputs)?;
        tracing::debug!("generated query proof");

        let auth = CredentialBlindingFactorOprfRequestAuthV1 {
            proof: proof.into(),
            action: *action,
            nonce: *nonce,
            merkle_root: *authenticator_input.inclusion_proof.root,
            issuer_schema_id,
        };

        tracing::debug!("executing distributed OPRF");

        let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
            services,
            OprfModule::CredentialBlindingFactor.to_string().as_str(),
            threshold,
            oprf_key_id,
            *query_hash,
            query_blinding_factor,
            ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_PROOF_DS),
            auth,
            connector,
        )
        .await?;

        Ok(Self {
            verifiable_oprf_output,
        })
    }
}
