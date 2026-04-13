use super::constants::DS_C_CS;
use poseidon2::bn254::perm;

pub(crate) fn generate_message(mt_index: Field, query: Field) -> Field {
    // Only registered domain separators are allowed per WIP-103. Currently only: `DS_C_CS` (WIP-103-001)
    let state = perm::x5_3([DS_C_CS, mt_index, query]);
    state[1]
}

#[test]
fn test_generate_message_deterministic() {
    let msg1 = generate_message(1, 100);
    let msg2 = generate_message(1, 100);
    assert_eq(msg1, msg2);
}

#[test]
fn test_generate_message_different_inputs() {
    let msg1 = generate_message(1, 100);
    let msg2 = generate_message(2, 100);
    assert(msg1 != msg2);

    let msg3 = generate_message(1, 200);
    assert(msg1 != msg3);
}
