pub(crate) mod constants;
pub(crate) mod types;
pub(crate) mod commitment;
pub(crate) mod merkle_proof;

use commitment::{generate_commitment, generate_message};
use constants::{MAX_DEPTH, NUM_KEYS};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use merkle_proof::{compute_merkle_root_poseidon2, merkle_leaf};
use std::field::bn254::assert_lt;
use types::OwnershipProofInputs;

pub fn main(
    merkle_root: pub Field,
    depth: pub Field,
    nonce: pub Field,
    expected_commitment: pub Field,
    context: pub Field,
    inputs: OwnershipProofInputs<MAX_DEPTH, NUM_KEYS>,
) {
    // 1. Generate query commitment and verify
    let commitment =
        generate_commitment(inputs.merkle_proof.leaf_index, inputs.commitment_blinder);
    assert(commitment == expected_commitment, "commitment mismatch");

    // 2. Verify authenticator signature to the expected message
    assert_lt(inputs.pk_index, NUM_KEYS as Field);
    let message = generate_message(commitment, nonce, context);
    let chosen_pk = inputs.user_pk[inputs.pk_index as u32];

    let is_valid = verify_eddsa_poseidon2(
        chosen_pk.x,
        chosen_pk.y,
        inputs.query_s,
        inputs.query_r,
        message,
    );
    assert(is_valid, "invalid signature");

    // 3. Compute and verify merkle inclusion proof
    let merkle_leaf = merkle_leaf(inputs.user_pk);
    let computed_root = compute_merkle_root_poseidon2(
        merkle_leaf,
        depth,
        inputs.merkle_proof.leaf_index,
        inputs.merkle_proof.siblings,
    );
    assert(computed_root == merkle_root, "merkle proof verification failed");
}
