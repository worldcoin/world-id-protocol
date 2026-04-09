use super::constants::DS_C_CS;
use poseidon2::bn254::perm;

pub(crate) fn generate_message(domain_separator: Field, mt_index: Field, query: Field) -> Field {
    // Supported domain separators. Only registered domain separators are allowed per WIP-103.
    // We accept the domain separator as a public input to allow introducing others without breaking changes.
    assert(domain_separator == DS_C_CS);

    let state = perm::x5_3([domain_separator, mt_index, query]);
    state[1]
}

#[test]
fn test_generate_message_deterministic() {
    let msg1 = generate_message(DS_C_CS, 1, 100);
    let msg2 = generate_message(DS_C_CS, 1, 100);
    assert_eq(msg1, msg2);
}

#[test]
fn test_generate_message_different_inputs() {
    let msg1 = generate_message(DS_C_CS, 1, 100);
    let msg2 = generate_message(DS_C_CS, 2, 100);
    assert(msg1 != msg2);

    let msg3 = generate_message(DS_C_CS, 1, 200);
    assert(msg1 != msg3);
}

#[test(should_fail)]
fn test_rejects_ds_zero() {
    let _ = generate_message(0, 1, 100);
}

#[test(should_fail)]
fn test_rejects_ds_one() {
    let _ = generate_message(1, 1, 100);
}

#[test(should_fail)]
fn test_rejects_ds_off_by_one() {
    let _ = generate_message(87492525752134038588518952, 1, 100);
}
