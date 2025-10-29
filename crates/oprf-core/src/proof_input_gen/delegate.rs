use crate::{
    oprf::{BlindedOPrfRequest, BlindingFactor, OPrfKey, OPrfService, OprfClient},
    proof_input_gen::{query::QueryProofInput, rpid_query::RpIdQueryProofInput},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use poseidon2::{Poseidon2, field_from_hex_string};
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use std::array;

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

#[derive(Debug, Clone)]
pub struct DelegateProofInput<const MAX_DEPTH: usize, const RP_MAX_DEPTH: usize> {
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
    // Dlog Equality Proof
    pub dlog_e: BaseField,
    pub dlog_s: ScalarField,
    pub oprf_pk: [BaseField; 2],
    pub oprf_response_blinded: [BaseField; 2],
    // Unblinded response
    pub oprf_response: [BaseField; 2],
    // Nonce
    pub nonce: BaseField,
    // Commitment to the id
    pub id_commitment_r: BaseField,
    // secret key for the encryption of the shares
    pub encryption_sk: ScalarField,
    pub mpc_public_keys: [[BaseField; 2]; 3],
    // Merkle proof for the RP registry
    pub rp_merkle_root: BaseField,
    pub rp_depth: BaseField,
    pub rp_mt_index: BaseField,
    pub rp_siblings: [BaseField; RP_MAX_DEPTH],
    // secret shares
    pub map_id_share: [BaseField; 3],
    pub r_share: [BaseField; 3],
    pub expiration: BaseField,
    // Outputs
    pub id_commitment: BaseField,
    pub map_id_commitment: BaseField,
    pub encryption_pk: [BaseField; 2],
    pub ciphertexts: [[BaseField; 4]; 3],
}

impl<const MAX_DEPTH: usize, const RP_MAX_DEPTH: usize>
    DelegateProofInput<MAX_DEPTH, RP_MAX_DEPTH>
{
    pub const MAX_PUBLIC_KEYS: usize = RpIdQueryProofInput::<MAX_DEPTH>::MAX_PUBLIC_KEYS;

    // Absorb 2, squeeze 3, absorb 3, squeeze 1, domainsep = 0x4142
    // [0x80000002, 0x00000003, 0x80000003, 0x00000001, 0x4142]
    const T3: &str = "0x800000020000000380000003000000014142";

    pub fn generate_from_seed(seed: &[u8; 32]) -> Self {
        let mut rng = ChaCha12Rng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    fn get_t3_ds() -> BaseField {
        field_from_hex_string(Self::T3).expect("Should fit in the field")
    }

    #[expect(clippy::manual_memcpy)]
    // Implements encryption following Algorithm 7 from the SAFE-API paper (https://eprint.iacr.org/2023/522.pdf)
    fn ae_encrypt(
        key: BaseField,
        mut ptxt: [BaseField; 3],
        nonce: BaseField,
    ) -> ([BaseField; 3], BaseField) {
        let poseidon2_4 = Poseidon2::<_, 4, 5>::default();
        let mut state =
            poseidon2_4.permutation(&[Self::get_t3_ds(), key, nonce, BaseField::zero()]);
        for i in 0..3 {
            state[i + 1] += ptxt[i];
            ptxt[i] = state[i + 1];
        }
        let tag = poseidon2_4.permutation(&state)[1];
        (ptxt, tag)
    }

    #[expect(unused)]
    // Implements decryption following Algorithm 7 from the SAFE-API paper (https://eprint.iacr.org/2023/522.pdf)
    fn ae_decrypt(
        key: BaseField,
        mut ctxt: [BaseField; 3],
        tag: BaseField,
        nonce: BaseField,
    ) -> std::io::Result<[BaseField; 3]> {
        let poseidon2_4 = Poseidon2::<_, 4, 5>::default();
        let mut state =
            poseidon2_4.permutation(&[Self::get_t3_ds(), key, nonce, BaseField::zero()]);
        for i in 0..3 {
            let ptxt = ctxt[i] - state[i + 1];
            state[i + 1] = ctxt[i];
            ctxt[i] = ptxt;
        }
        let is_tag = poseidon2_4.permutation(&state)[1];
        if is_tag != tag {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "tag does not match",
            ));
        }
        Ok(ctxt)
    }

    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        //  Random inputs
        let sk = OPrfKey::new(ScalarField::rand(rng));
        let id_commitment_r = BaseField::rand(rng);
        let encryption_sk = ScalarField::rand(rng);
        let rp_mt_index_u64 = rng.gen_range(0..(1 << RP_MAX_DEPTH)) as u64;
        let rp_mt_index = BaseField::from(rp_mt_index_u64);
        let r_share = [
            BaseField::rand(rng),
            BaseField::rand(rng),
            BaseField::rand(rng),
        ];
        let map_id_commitment_r = r_share.iter().fold(BaseField::zero(), |acc, x| acc + *x);
        let mut map_id_share = [
            BaseField::rand(rng),
            BaseField::rand(rng),
            BaseField::zero(),
        ];
        map_id_share[2] = rp_mt_index - map_id_share[0] - map_id_share[1];
        let rp_siblings: [BaseField; RP_MAX_DEPTH] = array::from_fn(|_| BaseField::rand(rng));
        let expiration = BaseField::rand(rng);

        // Create the query proof
        let (query_proof_input, query) = RpIdQueryProofInput::<MAX_DEPTH>::generate(rng);

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

        // The rp specific id is the OPRF result
        let rp_specific_id = oprf_client
            .finalize_query(oprf_blinded_response.to_owned(), blinding_factor_prepared)
            .expect("IDs should match");

        // lets commit to the id
        let id_commitment = OprfClient::id_commitment(query_proof_input.mt_index, id_commitment_r);

        // lets commit to the map id
        let map_id_commitment = OprfClient::id_commitment(rp_mt_index, map_id_commitment_r);

        // Compute the Merkle root
        let rp_merkle_root = QueryProofInput::<RP_MAX_DEPTH>::merkle_root(
            rp_specific_id,
            &rp_siblings,
            rp_mt_index_u64,
        );

        // derive encryption keys from the public keys
        let encryption_pk = (Affine::generator() * encryption_sk).into_affine();
        let mut encryption_keys = [Default::default(); 3];
        let mut mpc_public_keys = [[Default::default(); 2]; 3];
        for i in 0..3 {
            let sk = ScalarField::rand(rng);
            let pk = (Affine::generator() * sk).into_affine();
            let encryption_key = Self::dh_key_derivation(encryption_sk, pk);
            encryption_keys[i] = encryption_key;
            mpc_public_keys[i] = [pk.x, pk.y];
        }

        // Encrypt the shares
        let mut ciphertexts = [[BaseField::default(); 4]; 3];
        for i in 0..3 {
            let (ctxt, tag) = Self::ae_encrypt(
                encryption_keys[i],
                [map_id_share[i], r_share[i], expiration],
                BaseField::zero(), // We don't use a nonce since it is a one-time encryption with a fresh key
            );
            ciphertexts[i] = [ctxt[0], ctxt[1], ctxt[2], tag];
        }

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
            dlog_e: dlog_proof.e,
            dlog_s: dlog_proof.s,
            oprf_response_blinded: [
                oprf_blinded_response.blinded_response.x,
                oprf_blinded_response.blinded_response.y,
            ],
            oprf_response: [unblinded_response.x, unblinded_response.y],
            oprf_pk: [oprf_service.public_key().x, oprf_service.public_key().y],
            nonce: query_proof_input.nonce,
            id_commitment_r,
            id_commitment,
            encryption_sk,
            mpc_public_keys,
            rp_merkle_root,
            rp_depth: BaseField::from(RP_MAX_DEPTH as u64),
            rp_mt_index,
            rp_siblings,
            map_id_share,
            r_share,
            expiration,
            map_id_commitment,
            encryption_pk: [encryption_pk.x, encryption_pk.y],
            ciphertexts,
        }
    }

    fn dh_key_derivation(my_sk: ScalarField, their_pk: Affine) -> BaseField {
        (their_pk * my_sk).into_affine().x
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
        println!("nonce: {}n,", self.nonce);
        println!("id_commitment_r: {}n,", self.id_commitment_r);
        println!("encryption_sk: {}n,", self.encryption_sk);
        println!("mpc_public_keys: [");
        for (i, pk) in self.mpc_public_keys.iter().enumerate() {
            if i < self.mpc_public_keys.len() - 1 {
                println!("  [{:?}n, {:?}n],", pk[0], pk[1]);
            } else {
                println!("  [{:?}n, {:?}n]", pk[0], pk[1]);
            }
        }
        println!("],");
        println!("rp_merkle_root: {}n,", self.rp_merkle_root);
        println!("rp_depth: {}n,", self.rp_depth);
        println!("rp_mt_index: {}n,", self.rp_mt_index);
        println!("rp_siblings: [");
        for (i, s) in self.rp_siblings.iter().enumerate() {
            if i < self.rp_siblings.len() - 1 {
                println!("  {}n,", s);
            } else {
                println!("  {}n", s);
            }
        }
        println!("],");
        println!("map_id_share: [");
        for (i, share) in self.map_id_share.iter().enumerate() {
            if i < self.map_id_share.len() - 1 {
                println!("  {}n,", share);
            } else {
                println!("  {}n", share);
            }
        }
        println!("],");
        println!("r_share: [");
        for (i, share) in self.r_share.iter().enumerate() {
            if i < self.r_share.len() - 1 {
                println!("  {}n,", share);
            } else {
                println!("  {}n", share);
            }
        }
        println!("],");
        println!("expiration: {}n,", self.expiration);
        println!("id_commitment: {}n,", self.id_commitment);
        println!("map_id_commitment: {}n,", self.map_id_commitment);
        println!(
            "encryption_pk: [{:?}n, {:?}n],",
            self.encryption_pk[0], self.encryption_pk[1]
        );
        println!("ciphertexts: [");
        for (i, ctxt) in self.ciphertexts.iter().enumerate() {
            if i < self.ciphertexts.len() - 1 {
                println!(
                    "  [{:?}n, {:?}n, {:?}n, {:?}n],",
                    ctxt[0], ctxt[1], ctxt[2], ctxt[3]
                );
            } else {
                println!(
                    "  [{:?}n, {:?}n, {:?}n, {:?}n]",
                    ctxt[0], ctxt[1], ctxt[2], ctxt[3]
                );
            }
        }
        println!("],");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::array;

    #[test]
    fn test_delegate_proof_input_10() {
        let seed = array::from_fn(|i| i as u8);
        let input1 = DelegateProofInput::<10, 10>::generate_from_seed(&seed);
        input1.print();
    }
}
