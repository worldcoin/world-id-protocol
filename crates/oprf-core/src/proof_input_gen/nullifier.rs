use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use uuid::Uuid;

use crate::{
    dlog_equality::DLogEqualityProof,
    oprf::{
        BlindedOPrfRequest, BlindedOPrfResponse, BlindingFactor, OPrfKey, OPrfService, OprfClient,
    },
    proof_input_gen::query::QueryProofInput,
};

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

#[derive(Debug, Clone)]
pub struct NullifierProofInput<const MAX_DEPTH: usize> {
    // Signature
    pub user_pk: [[BaseField; 2]; super::query::MAX_PUBLIC_KEYS],
    pub pk_index: BaseField, // 0..6
    pub query_s: ScalarField,
    pub query_r: [BaseField; 2],
    // Credential Signature
    pub cred_type_id: BaseField,
    pub cred_pk: [BaseField; 2],
    pub cred_hashes: [BaseField; 2], // [claims_hash, associated_data_hash]
    pub cred_genesis_issued_at: BaseField,
    pub cred_expires_at: BaseField,
    pub cred_s: ScalarField,
    pub cred_r: [BaseField; 2],
    pub current_time_stamp: BaseField,
    // Merkle proof
    pub merkle_root: BaseField,
    pub depth: BaseField,
    pub mt_index: BaseField,
    pub siblings: [BaseField; MAX_DEPTH],
    // OPRF query
    pub beta: ScalarField,
    pub rp_id: BaseField,
    pub action: BaseField,
    // Dlog Equality Proof
    pub dlog_e: BaseField,
    pub dlog_s: ScalarField,
    pub oprf_pk: [BaseField; 2],
    pub oprf_response_blinded: [BaseField; 2],
    // Unblinded response
    pub oprf_response: [BaseField; 2],
    // SignalHash as in Semaphore
    pub signal_hash: BaseField,
    pub nonce: BaseField,
    // Commitment to the id
    pub id_commitment_r: BaseField,
    // Outputs
    pub id_commitment: BaseField,
    pub nullifier: BaseField,
}

impl<const MAX_DEPTH: usize> NullifierProofInput<MAX_DEPTH> {
    pub const MAX_PUBLIC_KEYS: usize = QueryProofInput::<MAX_DEPTH>::MAX_PUBLIC_KEYS;

    pub fn generate_from_seed(seed: &[u8; 32]) -> Self {
        let mut rng = ChaCha12Rng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        //  Random inputs
        let sk = OPrfKey::new(ScalarField::rand(rng));
        let signal_hash = BaseField::rand(rng);
        let id_commitment_r = BaseField::rand(rng);

        // Create the query proof
        let (query_proof_input, query) = QueryProofInput::<MAX_DEPTH>::generate(rng);

        // These come from the QueryProof, but need to be reconstructed
        let blinded_query = Affine::new_unchecked(query_proof_input.q[0], query_proof_input.q[1]);
        let blinded_oprf_query = BlindedOPrfRequest {
            request_id: uuid::Uuid::new_v4(),
            blinded_query,
        };
        let blinding_factor = BlindingFactor {
            factor: query_proof_input.beta,
            query,
            request_id: blinded_oprf_query.request_id,
        };
        let blinding_factor_prepared = blinding_factor.prepare();

        // The OPRF response and proof
        let oprf_service = OPrfService::new(sk);
        let (oprf_blinded_response, dlog_proof) =
            oprf_service.answer_query_with_proof(blinded_oprf_query);

        // Now the client finalizes the nullifier
        let pk_index = query_proof_input.pk_index.into_bigint().0[0] as usize;
        let pk = query_proof_input.pk[pk_index];
        let client_pk = Affine::new_unchecked(pk[0], pk[1]);
        let oprf_client = OprfClient::new(client_pk);

        // We need an intermediate result
        let unblinded_response = (oprf_blinded_response.blinded_response
            * blinding_factor_prepared.factor)
            .into_affine();

        let nullifier = oprf_client
            .finalize_query(oprf_blinded_response.to_owned(), blinding_factor_prepared)
            .expect("IDs should match");

        // lets commit to the id
        let id_commitment = OprfClient::id_commitment(query_proof_input.mt_index, id_commitment_r);

        Self {
            user_pk: query_proof_input.pk,
            pk_index: query_proof_input.pk_index,
            query_s: query_proof_input.s,
            query_r: query_proof_input.r,
            cred_type_id: query_proof_input.cred_type_id,
            cred_pk: query_proof_input.cred_pk,
            cred_hashes: query_proof_input.cred_hashes,
            cred_genesis_issued_at: query_proof_input.cred_genesis_issued_at,
            cred_expires_at: query_proof_input.cred_expires_at,
            cred_s: query_proof_input.cred_s,
            cred_r: query_proof_input.cred_r,
            current_time_stamp: query_proof_input.current_time_stamp,
            merkle_root: query_proof_input.merkle_root,
            depth: query_proof_input.depth,
            mt_index: query_proof_input.mt_index,
            siblings: query_proof_input.siblings,
            beta: query_proof_input.beta,
            rp_id: query_proof_input.rp_id,
            action: query_proof_input.action,
            dlog_e: dlog_proof.e,
            dlog_s: dlog_proof.s,
            oprf_response_blinded: [
                oprf_blinded_response.blinded_response.x,
                oprf_blinded_response.blinded_response.y,
            ],
            oprf_response: [unblinded_response.x, unblinded_response.y],
            oprf_pk: [oprf_service.public_key().x, oprf_service.public_key().y],
            signal_hash,
            nonce: query_proof_input.nonce,
            id_commitment_r,
            id_commitment,
            nullifier,
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        oprf_pk: Affine,
        signal_hash: BaseField,
        query_proof_input: QueryProofInput<MAX_DEPTH>,
        query: BaseField,
        blinded_response: Affine,
        dlog_proof: DLogEqualityProof,
        id_commitment_r: BaseField,
    ) -> Self {
        // These come from the QueryProof, but need to be reconstructed
        let blinding_factor = BlindingFactor {
            factor: query_proof_input.beta,
            query,
            request_id,
        };
        let blinding_factor_prepared = blinding_factor.prepare();

        let oprf_blinded_response = BlindedOPrfResponse {
            request_id,
            blinded_response,
        };

        // Now the client finalizes the nullifier
        let pk_index = query_proof_input.pk_index.into_bigint().0[0] as usize;
        let pk = query_proof_input.pk[pk_index];
        let client_pk = Affine::new_unchecked(pk[0], pk[1]);
        let oprf_client = OprfClient::new(client_pk);

        // We need an intermediate result
        let unblinded_response = (oprf_blinded_response.blinded_response
            * blinding_factor_prepared.factor)
            .into_affine();

        let nullifier = oprf_client
            .finalize_query(oprf_blinded_response.to_owned(), blinding_factor_prepared)
            .expect("IDs should match");

        // lets commit to the id
        let id_commitment = OprfClient::id_commitment(query_proof_input.mt_index, id_commitment_r);

        Self {
            user_pk: query_proof_input.pk,
            pk_index: query_proof_input.pk_index,
            query_s: query_proof_input.s,
            query_r: query_proof_input.r,
            cred_type_id: query_proof_input.cred_type_id,
            cred_pk: query_proof_input.cred_pk,
            cred_hashes: query_proof_input.cred_hashes,
            cred_genesis_issued_at: query_proof_input.cred_genesis_issued_at,
            cred_expires_at: query_proof_input.cred_expires_at,
            cred_s: query_proof_input.cred_s,
            cred_r: query_proof_input.cred_r,
            current_time_stamp: query_proof_input.current_time_stamp,
            merkle_root: query_proof_input.merkle_root,
            depth: query_proof_input.depth,
            mt_index: query_proof_input.mt_index,
            siblings: query_proof_input.siblings,
            beta: query_proof_input.beta,
            rp_id: query_proof_input.rp_id,
            action: query_proof_input.action,
            dlog_e: dlog_proof.e,
            dlog_s: dlog_proof.s,
            oprf_response_blinded: [
                oprf_blinded_response.blinded_response.x,
                oprf_blinded_response.blinded_response.y,
            ],
            oprf_response: [unblinded_response.x, unblinded_response.y],
            oprf_pk: [oprf_pk.x, oprf_pk.y],
            signal_hash,
            nonce: query_proof_input.nonce,
            id_commitment_r,
            id_commitment,
            nullifier,
        }
    }

    pub fn print(&self) {
        println!("user_pk: [");
        for (i, pk) in self.user_pk.iter().enumerate() {
            if i < self.user_pk.len() - 1 {
                println!("  [{:?}n, {:?}n],", pk[0], pk[1]);
            } else {
                println!("  [{:?}n, {:?}n]", pk[0], pk[1]);
            }
        }
        println!("],");
        println!("pk_index: {}n,", self.pk_index);
        println!("query_s: {}n,", self.query_s);
        println!("query_r: [{}n, {}n],", self.query_r[0], self.query_r[1]);
        println!("cred_type_id: {}n,", self.cred_type_id);
        println!("cred_pk: [{:?}n, {:?}n],", self.cred_pk[0], self.cred_pk[1]);
        println!(
            "cred_hashes: [{:?}n, {:?}n],",
            self.cred_hashes[0], self.cred_hashes[1]
        );
        println!("cred_genesis_issued_at: {}n,", self.cred_genesis_issued_at);
        println!("cred_expires_at: {}n,", self.cred_expires_at);
        println!("cred_s: {}n,", self.cred_s);
        println!("cred_r: [{}n, {}n],", self.cred_r[0], self.cred_r[1]);
        println!("current_time_stamp: {}n,", self.current_time_stamp);
        println!("merkle_root: {}n,", self.merkle_root);
        println!("depth: {}n,", self.depth);
        println!("mt_index: {}n,", self.mt_index);
        println!("siblings: [");
        for (i, s) in self.siblings.iter().enumerate() {
            if i < self.siblings.len() - 1 {
                println!("  {}n,", s);
            } else {
                println!("  {}n", s);
            }
        }
        println!("],");
        println!("beta: {}n,", self.beta);
        println!("rp_id: {}n,", self.rp_id);
        println!("action: {}n,", self.action);
        println!("dlog_e: {}n,", self.dlog_e);
        println!("dlog_s: {}n,", self.dlog_s);
        println!("oprf_pk: [{}n, {}n],", self.oprf_pk[0], self.oprf_pk[1]);
        println!(
            "oprf_response_blinded: [{}n, {}n],",
            self.oprf_response_blinded[0], self.oprf_response_blinded[1]
        );
        println!(
            "oprf_response: [{}n, {}n],",
            self.oprf_response[0], self.oprf_response[1]
        );
        println!("signal_hash: {}n,", self.signal_hash);
        println!("nonce: {}n,", self.nonce);
        println!("id_commitment_r: {}n,", self.id_commitment_r);
        println!("id_commitment: {}n,", self.id_commitment);
        println!("nullifier: {}n,", self.nullifier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::array;

    #[test]
    fn test_nullifier_proof_input_10() {
        let seed = array::from_fn(|i| i as u8);
        let input1 = NullifierProofInput::<10>::generate_from_seed(&seed);
        input1.print();
    }
}
