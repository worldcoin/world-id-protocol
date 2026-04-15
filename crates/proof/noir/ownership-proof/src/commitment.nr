use super::constants::{DS_C_CS, DS_OWNERSHIP_PROOF};
use poseidon2::bn254::perm;

pub(crate) fn generate_commitment(mt_index: Field, query: Field) -> Field {
    // Only registered domain separators are allowed per WIP-103. Currently only: `DS_C_CS` (WIP-103-001)
    let state = perm::x5_3([DS_C_CS, mt_index, query]);
    state[1]
}

pub(crate) fn generate_message(commitment: Field, nonce: Field) -> Field {
    let state = perm::x5_3([DS_OWNERSHIP_PROOF, commitment, nonce]);
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
