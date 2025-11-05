use ark_ec::CurveGroup;
use oprf_core::{
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOPrfResponse, BlindingFactor},
};
use serde::Serialize;
use uuid::Uuid;

use crate::proof_inputs::query::QueryProofInput;

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

#[derive(Debug, Clone, Serialize)]
pub struct NullifierProofInput<const MAX_DEPTH: usize> {
    #[serde(flatten)]
    pub query_input: QueryProofInput<MAX_DEPTH>,
    // Dlog Equality Proof
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub dlog_e: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    pub dlog_s: ScalarField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub oprf_pk: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub oprf_response_blinded: Affine,
    // Unblinded response
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub oprf_response: Affine,
    // SignalHash as in Semaphore
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub signal_hash: BaseField,
    // Commitment to the id
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub id_commitment_r: BaseField,
}

impl<const MAX_DEPTH: usize> NullifierProofInput<MAX_DEPTH> {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        query_input: QueryProofInput<MAX_DEPTH>,
        dlog_proof: DLogEqualityProof,
        oprf_pk: Affine,
        blinded_response: Affine,
        signal_hash: BaseField,
        id_commitment_r: BaseField,
        query: BaseField,
    ) -> Self {
        let blinding_factor = BlindingFactor {
            factor: query_input.beta,
            query,
            request_id,
        };
        let blinding_factor_prepared = blinding_factor.prepare();

        let oprf_blinded_response = BlindedOPrfResponse {
            request_id,
            blinded_response,
        };

        let unblinded_response = (oprf_blinded_response.blinded_response
            * blinding_factor_prepared.factor)
            .into_affine();

        Self {
            query_input,
            dlog_e: dlog_proof.e,
            dlog_s: dlog_proof.s,
            oprf_response_blinded: oprf_blinded_response.blinded_response,
            oprf_response: unblinded_response,
            oprf_pk,
            signal_hash,
            id_commitment_r,
        }
    }
}
