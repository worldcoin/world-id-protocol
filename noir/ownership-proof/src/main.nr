pub(crate) mod constants;
pub(crate) mod types;
pub(crate) mod commitment;
pub(crate) mod merkle_proof;

use commitment::generate_message;
use constants::{MAX_DEPTH, NUM_KEYS};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use merkle_proof::{compute_merkle_root_poseidon2, merkle_leaf};
use std::field::bn254::assert_lt;
use types::{OwnershipProofInputs, OwnershipProofOutputs};

pub fn main(
    root: pub Field,
    depth: pub Field,
    nonce: pub Field,
    inputs: OwnershipProofInputs<MAX_DEPTH, NUM_KEYS>,
) -> pub OwnershipProofOutputs {
    // 1. Generate query
    let message = generate_message(inputs.merkle_proof.mt_index, inputs.commitment_r);

    // 1. Verify sk/pk by verifying a signature to a known message
    assert_lt(inputs.pk_index, NUM_KEYS as Field);
    let chosen_pk = inputs.user_pk[inputs.pk_index as u32];

    let is_valid = verify_eddsa_poseidon2(
        chosen_pk.x,
        chosen_pk.y,
        inputs.query_s,
        inputs.query_r,
        message,
    );
    assert(is_valid, "Invalid signature");

    // Compute and verify merkle proof
    let merkle_leaf = merkle_leaf(inputs.user_pk);
    let computed_root = compute_merkle_root_poseidon2(
        merkle_leaf,
        depth,
        inputs.merkle_proof.mt_index,
        inputs.merkle_proof.siblings,
    );
    assert(computed_root == root, "Merkle proof verification failed");

    // SAFETY: The multiplication is constrained below, this is just to emulate the signal hash coming from Circom/Semaphore
    let nonce_squared = unsafe { unconstrained_mul(nonce, nonce) };
    assert(nonce_squared == nonce * nonce, "Nonce dummy constraint failed");

    OwnershipProofOutputs { commitment: message }
}

unconstrained fn unconstrained_mul(a: Field, b: Field) -> Field {
    a * b
}
