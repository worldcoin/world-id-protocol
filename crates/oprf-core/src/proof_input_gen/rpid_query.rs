use std::array;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use eddsa_babyjubjub::EdDSAPrivateKey;
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use uuid::Uuid;

use crate::{oprf::OprfClient, proof_input_gen::query::QueryProofInput};

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;

#[derive(Debug, Clone)]
pub struct RpIdQueryProofInput<const MAX_DEPTH: usize> {
    // Signature
    pub pk: [[BaseField; 2]; super::query::MAX_PUBLIC_KEYS],
    pub pk_index: BaseField, // 0..6
    pub s: ScalarField,
    pub r: [BaseField; 2],
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
    pub nonce: BaseField,
    // Outputs
    pub q: [BaseField; 2],
}

impl<const MAX_DEPTH: usize> RpIdQueryProofInput<MAX_DEPTH> {
    pub const MAX_PUBLIC_KEYS: usize = QueryProofInput::<MAX_DEPTH>::MAX_PUBLIC_KEYS;

    pub fn generate_from_seed(seed: &[u8; 32]) -> (Self, BaseField) {
        let mut rng = ChaCha12Rng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    // Also returns the query, since this is used in the RP-specific proof input generation
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> (Self, BaseField) {
        // Random inputs
        let request_id = Uuid::new_v4();
        let sk = EdDSAPrivateKey::random(rng);
        let mt_index_u64 = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
        let mt_index = BaseField::from(mt_index_u64);
        let siblings: [BaseField; MAX_DEPTH] = array::from_fn(|_| BaseField::rand(rng));
        let pk_index_u64 = rng.gen_range(0..Self::MAX_PUBLIC_KEYS) as u64;
        let pk_index = BaseField::from(pk_index_u64);
        let nonce = BaseField::rand(rng);
        // For the credential signature
        let cred_type_id = BaseField::rand(rng);
        let cred_sk = EdDSAPrivateKey::random(rng);
        let cred_pk = cred_sk.public();
        let cred_hashes = [BaseField::rand(rng), BaseField::rand(rng)]; // In practice, these are 2 hashes
        let genesis_issued_at = BaseField::from(rng.r#gen::<u64>());
        let expired_at_u64 = rng.gen_range(1..=u64::MAX);
        let current_time_stamp = BaseField::from(rng.gen_range(0..expired_at_u64));
        let expired_at = BaseField::from(expired_at_u64);

        // Credential signature
        let cred_msg = super::query::QueryProofInput::<MAX_DEPTH>::credential_message(
            cred_type_id,
            mt_index,
            genesis_issued_at,
            expired_at,
            cred_hashes,
        );
        let cred_signature = cred_sk.sign(cred_msg);

        // Calculate public keys
        let pk = sk.public();
        let mut pks = [[BaseField::zero(); 2]; super::query::MAX_PUBLIC_KEYS];
        for (i, pki) in pks.iter_mut().enumerate() {
            if i as u64 == pk_index_u64 {
                pki[0] = pk.pk.x;
                pki[1] = pk.pk.y;
            } else {
                let sk_i = ScalarField::rand(rng);
                let pk_i = (ark_babyjubjub::EdwardsAffine::generator() * sk_i).into_affine();
                pki[0] = pk_i.x;
                pki[1] = pk_i.y;
            }
        }

        // Calculate OPRF
        let oprf_client = OprfClient::new(pk.pk);
        let (blinded_request, blinding_factor) = oprf_client.blind_query(request_id, mt_index, rng);

        // Sign the query
        let signature = sk.sign(blinding_factor.query);
        // Compute the Merkle root
        let merkkle_root =
            QueryProofInput::<MAX_DEPTH>::merkle_root_from_pks(&pks, &siblings, mt_index_u64);

        let result = Self {
            pk: pks,
            pk_index,
            s: signature.s,
            r: [signature.r.x, signature.r.y],
            cred_type_id,
            cred_pk: [cred_pk.pk.x, cred_pk.pk.y],
            cred_hashes,
            cred_genesis_issued_at: genesis_issued_at,
            cred_expires_at: expired_at,
            cred_s: cred_signature.s,
            cred_r: [cred_signature.r.x, cred_signature.r.y],
            current_time_stamp,
            merkle_root: merkkle_root,
            depth: BaseField::from(MAX_DEPTH as u64),
            mt_index,
            siblings,
            beta: blinding_factor.factor,
            nonce,
            q: [
                blinded_request.blinded_query.x,
                blinded_request.blinded_query.y,
            ],
        };

        (result, blinding_factor.query)
    }

    pub fn print(&self) {
        println!("pk: [");
        for (i, pk) in self.pk.iter().enumerate() {
            if i < self.pk.len() - 1 {
                println!("  [{:?}n, {:?}n],", pk[0], pk[1]);
            } else {
                println!("  [{:?}n, {:?}n]", pk[0], pk[1]);
            }
        }
        println!("],");
        println!("pk_index: {}n,", self.pk_index);
        println!("s: {}n,", self.s);
        println!("r: [{}n, {}n],", self.r[0], self.r[1]);
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
        println!("nonce: {}n,", self.nonce);
        println!("q: [{}n, {}n],", self.q[0], self.q[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpid_query_proof_input_10() {
        let seed = array::from_fn(|i| i as u8);
        let input1 = RpIdQueryProofInput::<10>::generate_from_seed(&seed).0;
        input1.print();
    }
}
