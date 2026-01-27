use ark_ff::PrimeField;
use groth16_material::circom::CircomGroth16Material;
use poseidon2::Poseidon2;
use taceo_oprf_client::{Connector, VerifiableOprfOutput};
use world_id_primitives::{FieldElement, rp::RpId};

pub struct OprfNullifier {
    verifiable_output: VerifiableOprfOutput,
    nullifier: FieldElement,
}

impl OprfNullifier {
    const OPRF_QUERY_DS: &[u8] = b"World ID Query";

    pub fn from_request(
        services: &[String],
        threshold: usize,
        query_material: &CircomGroth16Material,
        args: SingleProofInput<TREE_DEPTH>,
        private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
        connector: Connector,
    ) -> Self {
        let query_hash = Self::query_hash(args.inclusion_proof.leaf_index, args.rp_id, args.action);
    }

    /// Helper function to compute the query hash for a given account, RP ID, and action.
    #[must_use]
    pub fn query_hash(leaf_index: u64, rp_id: RpId, action: FieldElement) -> ark_babyjubjub::Fq {
        let input = [
            ark_babyjubjub::Fq::from_be_bytes_mod_order(Self::OPRF_QUERY_DS),
            leaf_index.into(),
            *FieldElement::from(rp_id),
            *action,
        ];
        let poseidon2_4: Poseidon2<ark_babyjubjub::Fq, 4, 5> = Poseidon2::default();
        poseidon2_4.permutation(&input)[1]
    }
}
