mod commitment;
pub mod constants;
mod merkle_proof;
mod types;

use commitment::{mixed_authenticator_set_commitment, passkey_slot_commitment};
use constants::{NUM_KEYS, P256_LIMBS};
use merkle_proof::compute_merkle_root_poseidon2;
use std::field::bn254::assert_lt;
use types::PasskeyOwnershipInputs;

fn assert_public_key_limbs_match(
    signed_public_key_x_limbs: [u128; P256_LIMBS],
    signed_public_key_y_limbs: [u128; P256_LIMBS],
    committed_public_key_x_limbs: [Field; P256_LIMBS],
    committed_public_key_y_limbs: [Field; P256_LIMBS],
) {
    for i in 0..P256_LIMBS {
        assert(
            signed_public_key_x_limbs[i] as Field == committed_public_key_x_limbs[i],
            "signed and committed public key x limbs differ",
        );
        assert(
            signed_public_key_y_limbs[i] as Field == committed_public_key_y_limbs[i],
            "signed and committed public key y limbs differ",
        );
    }
}

pub fn main(
    root: pub Field,
    challenge: pub [u8; 32],
    rp_id_hash: pub [u8; 32],
    inputs: PasskeyOwnershipInputs,
) {
    assert_public_key_limbs_match(
        inputs.webauthn.public_key_x_limbs,
        inputs.webauthn.public_key_y_limbs,
        inputs.public_key_x_limbs_field,
        inputs.public_key_y_limbs_field,
    );

    for i in 0..32 {
        assert(inputs.webauthn.authenticator_data.storage()[i] == rp_id_hash[i]);
    }

    let valid = webauthn::verify_signature(
        inputs.webauthn.public_key_x,
        inputs.webauthn.public_key_y,
        inputs.webauthn.signature,
        inputs.webauthn.client_data_json,
        inputs.webauthn.authenticator_data,
        challenge,
        inputs.webauthn.challenge_index,
        inputs.webauthn.r_point_y,
        inputs.webauthn.message_limbs,
        inputs.webauthn.public_key_x_limbs,
        inputs.webauthn.public_key_y_limbs,
        inputs.webauthn.signature_r_limbs,
        inputs.webauthn.signature_s_limbs,
        inputs.webauthn.r_point_y_limbs,
        inputs.webauthn.s_g_limbs,
        inputs.webauthn.s_g_slices,
        inputs.webauthn.s_g_skew,
        inputs.webauthn.s_g_borrow_low,
        inputs.webauthn.s_g_borrow_mid,
        inputs.webauthn.s_p_limbs,
        inputs.webauthn.s_p_slices,
        inputs.webauthn.s_p_skew,
        inputs.webauthn.s_p_borrow_low,
        inputs.webauthn.s_p_borrow_mid,
    );
    assert(valid, "webauthn signature verification failed");

    assert_lt(inputs.passkey_slot_index as Field, NUM_KEYS as Field);
    let expected_slot_commitment = passkey_slot_commitment(
        inputs.public_key_x_limbs_field,
        inputs.public_key_y_limbs_field,
    );
    assert(
        inputs.slot_commitments[inputs.passkey_slot_index] == expected_slot_commitment,
        "passkey slot commitment mismatch",
    );

    let account_leaf = mixed_authenticator_set_commitment(inputs.slot_commitments);
    let computed_root = compute_merkle_root_poseidon2(
        account_leaf,
        inputs.merkle_proof.leaf_index,
        inputs.merkle_proof.siblings,
    );
    assert(computed_root == root, "Merkle proof verification failed");
}

#[test]
fn test_signed_and_committed_public_key_limbs_match() {
    assert_public_key_limbs_match([1, 2, 3], [4, 5, 6], [1, 2, 3], [4, 5, 6]);
}

#[test(should_fail_with = "signed and committed public key x limbs differ")]
fn test_rejects_key_a_signature_with_key_b_slot_commitment() {
    // The first pair represents the key used by the WebAuthn signature, while
    // the second pair represents the different key committed in the registry slot.
    assert_public_key_limbs_match([1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12]);
}
