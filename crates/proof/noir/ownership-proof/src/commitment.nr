use super::constants::{DS_C_CS, DS_WIP_103};
use poseidon2::bn254::perm;

pub(crate) fn generate_commitment(leaf_index: Field, commitment_blinder: Field) -> Field {
    // Only registered domain separators are allowed per WIP-103. Currently only: `DS_C_CS` (WIP-103-001)
    let state = perm::x5_3([DS_C_CS, leaf_index, commitment_blinder]);
    state[1]
}

pub(crate) fn generate_message(commitment: Field, nonce: Field, context: Field) -> Field {
    let state = perm::x5_4([DS_WIP_103, commitment, nonce, context]);
    state[1]
}

#[test]
fn test_generate_commitment_deterministic() {
    let msg1 = generate_commitment(1, 100);
    let msg2 = generate_commitment(1, 100);
    assert_eq(msg1, msg2);
}

#[test]
fn test_generate_commitment_different_inputs() {
    let msg1 = generate_commitment(1, 100);
    let msg2 = generate_commitment(2, 100);
    assert(msg1 != msg2);

    let msg3 = generate_commitment(1, 200);
    assert(msg1 != msg3);
}

#[test]
fn test_generate_commitment_is_not_symmetric() {
    assert(generate_commitment(1, 100) != generate_commitment(100, 1));
}

#[test]
fn test_generate_message_deterministic() {
    assert_eq(generate_message(1, 100, 7), generate_message(1, 100, 7));
}

#[test]
fn test_generate_message_binds_every_input() {
    let message = generate_message(1, 100, 7);
    assert(message != generate_message(2, 100, 7));
    assert(message != generate_message(1, 200, 7));
    assert(message != generate_message(1, 100, 8));
}

#[test]
fn test_generate_message_is_not_symmetric() {
    assert(generate_message(1, 100, 7) != generate_message(1, 7, 100));
}

#[test]
fn test_commitment_and_message_are_domain_separated() {
    assert(generate_commitment(1, 100) != generate_message(1, 100, 0));
    assert(DS_C_CS != DS_WIP_103);
}
