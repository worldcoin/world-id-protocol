use super::constants::DS_WIP_103;
use poseidon2::bn254::permutation;
use world_id_components::credential::compute_sub;

pub(crate) fn generate_commitment(leaf_index: Field, commitment_blinder: Field) -> Field {
    // Only registered domain separators are allowed per WIP-103. Currently only the Credential
    // `sub` (WIP-103-001), `H_3(DS_CREDENTIAL_SUB; leaf_index, commitment_blinder)`.
    compute_sub(leaf_index, commitment_blinder)
}

pub(crate) fn generate_message(commitment: Field, nonce: Field, context: Field) -> Field {
    let state = permutation::t4([DS_WIP_103, commitment, nonce, context]);
    state[1]
}

#[test]
fn test_generate_commitment_known_answer() {
    assert_eq(
        generate_commitment(1, 100),
        0x26dc60a1544db4dad905da6967a536d6c37b3ae4b7cf951b925275096f5cbb1e,
    );
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
fn test_generate_message_known_answer() {
    assert_eq(
        generate_message(1, 100, 7),
        0x0574b3d43408903579cd25e90b560aa74fb096d4c65ce65c3b178fc9292032f4,
    );
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

use world_id_components::constants::DS_CREDENTIAL_SUB;

#[test]
fn test_commitment_and_message_are_domain_separated() {
    assert(generate_commitment(1, 100) != generate_message(1, 100, 0));
    assert(DS_CREDENTIAL_SUB != DS_WIP_103);
}
