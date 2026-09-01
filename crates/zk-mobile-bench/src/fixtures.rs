//! Fixture utilities for benchmark input generation.
//!
//! These utilities create valid circuit inputs without requiring
//! network calls or on-chain interactions.

use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use eddsa_babyjubjub::EdDSAPrivateKey;
use rand::{CryptoRng, Rng};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
    rp::RpId,
};
use world_id_proof::circuit_inputs::OwnershipProofCircuitInput;

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

/// Builds a deterministic, valid WIP-103 ownership-proof input.
pub fn ownership_proof_fixture() -> OwnershipProofCircuitInput<TREE_DEPTH> {
    const LEAF_INDEX: u64 = 1;

    let sk = EdDSAPrivateKey::from_bytes([42u8; 32]);
    let key_set = AuthenticatorPublicKeySet::new(vec![sk.public()]).expect("valid key set");
    let (siblings, root) = first_leaf_merkle_path(key_set.leaf_hash());
    let nonce = FieldElement::from(1_234_567_890u64);
    let context = FieldElement::from(42u64);
    let commitment_blinder = FieldElement::from(999u64);
    let expected_commitment = Credential::compute_sub(LEAF_INDEX, commitment_blinder);
    let message = poseidon::hash(ds::OWNERSHIP_PROOF, [expected_commitment, nonce, context]);

    OwnershipProofCircuitInput {
        key_index: 0,
        key_set,
        inclusion_proof: MerkleInclusionProof::new(root, LEAF_INDEX, siblings),
        nonce,
        expected_commitment,
        context,
        signature: sk.sign(*message),
        commitment_blinder,
    }
}

/// Builds the default-zero sibling path for index 1 and computes the Merkle root
/// after inserting the provided `leaf` at that index, using Poseidon2 T2 compress.
pub fn first_leaf_merkle_path(leaf: Fq) -> ([FieldElement; TREE_DEPTH], FieldElement) {
    let mut siblings = [FieldElement::ZERO; TREE_DEPTH];
    let mut zero = FieldElement::ZERO;
    for sibling in siblings.iter_mut() {
        *sibling = zero;
        zero = poseidon::compress(zero, zero);
    }

    let mut current = poseidon::compress(siblings[0], leaf.into());
    // For the remaining levels, continue hashing with current on the left
    for sibling in &siblings[1..] {
        current = poseidon::compress(current, *sibling);
    }

    (siblings, current)
}
