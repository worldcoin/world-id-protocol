use groth16_material::circom::ProofInput;
use oprf_core::{
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOprfResponse, BlindingFactor},
};

use crate::proof_inputs::query::QueryProofInput;

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

#[derive(Debug, Clone)]
pub struct NullifierProofInput<const MAX_DEPTH: usize> {
    pub query_input: QueryProofInput<MAX_DEPTH>,
    // Dlog Equality Proof
    pub dlog_e: BaseField,
    pub dlog_s: ScalarField,
    pub oprf_pk: Affine,
    pub oprf_response_blinded: Affine,
    // Unblinded response
    pub oprf_response: Affine,
    // SignalHash as in Semaphore
    pub signal_hash: BaseField,
    // Commitment to the id
    pub id_commitment_r: BaseField,
}

impl<const MAX_DEPTH: usize> NullifierProofInput<MAX_DEPTH> {
    pub fn new(
        query_input: QueryProofInput<MAX_DEPTH>,
        dlog_proof: DLogEqualityProof,
        oprf_pk: Affine,
        blinded_response: Affine,
        signal_hash: BaseField,
        id_commitment_r: BaseField,
        blinding_factor: BlindingFactor,
    ) -> Self {
        let blinding_factor_prepared = blinding_factor.prepare();

        let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);

        let unblinded_response = oprf_blinded_response.unblind_response(&blinding_factor_prepared);

        Self {
            query_input,
            dlog_e: dlog_proof.e,
            dlog_s: dlog_proof.s,
            oprf_response_blinded: oprf_blinded_response.response(),
            oprf_response: unblinded_response,
            oprf_pk,
            signal_hash,
            id_commitment_r,
        }
    }
}

impl<const MAX_DEPTH: usize> ProofInput for NullifierProofInput<MAX_DEPTH> {
    fn prepare_input(&self) -> std::collections::HashMap<String, Vec<ruint::aliases::U256>> {
        let mut map = self.query_input.prepare_input();
        map.insert("dlog_e".to_owned(), super::fq_to_u256_vec(self.dlog_e));
        map.insert("dlog_s".to_owned(), super::fr_to_u256_vec(self.dlog_s));
        map.insert(
            "oprf_pk".to_owned(),
            super::affine_to_u256_vec(self.oprf_pk),
        );
        map.insert(
            "oprf_response_blinded".to_owned(),
            super::affine_to_u256_vec(self.oprf_response_blinded),
        );
        map.insert(
            "oprf_response".to_owned(),
            super::affine_to_u256_vec(self.oprf_response),
        );
        map.insert(
            "signal_hash".to_owned(),
            super::fq_to_u256_vec(self.signal_hash),
        );
        map.insert(
            "id_commitment_r".to_owned(),
            super::fq_to_u256_vec(self.id_commitment_r),
        );
        map
    }
}
