//! Fixture utilities for benchmark input generation.
//!
//! These utilities create valid circuit inputs without requiring
//! network calls or on-chain interactions.

use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use rand::{CryptoRng, Rng};
use world_id_primitives::rp::RpId;

/// RP fixture data for benchmarks
pub struct RpFixture {
    pub world_rp_id: RpId,
    pub action: Fq,
    pub nonce: Fq,
    pub current_timestamp: u64,
    pub rp_secret: Fr,
    pub rp_nullifier_point: EdwardsAffine,
}

/// Generate RP fixture with deterministic randomness
pub fn generate_rp_fixture<R: Rng + CryptoRng>(rng: &mut R) -> RpFixture {
    let rp_id_value: u64 = rng.r#gen();
    let world_rp_id = RpId::new(rp_id_value);

    let action = Fq::rand(rng);
    let nonce = Fq::rand(rng);
    let current_timestamp = 1700000000u64; // Fixed for reproducibility

    let rp_secret = Fr::rand(rng);
    let rp_nullifier_point = (EdwardsAffine::generator() * rp_secret).into_affine();

    RpFixture {
        world_rp_id,
        action,
        nonce,
        current_timestamp,
        rp_secret,
        rp_nullifier_point,
    }
}

/// Builds the default-zero sibling path for index 1 and computes the Merkle root
/// after inserting the provided `leaf` at that index, using Poseidon2 T2 compress.
pub use world_id_primitives::merkle::first_leaf_merkle_path;
