mod commitment;
pub mod constants;
mod merkle_proof;
mod types;
mod webauthn;

use commitment::{
    mixed_authenticator_set_commitment, p256_be_bytes_to_limbs, passkey_slot_commitment,
};
use constants::NUM_KEYS;
use merkle_proof::compute_merkle_root_poseidon2;
use std::field::bn254::assert_lt;
use types::PasskeyOwnershipInputs;

pub fn main(
    root: pub Field,
    challenge: pub [u8; 32],
    rp_id_hash: pub [u8; 32],
    inputs: PasskeyOwnershipInputs,
) {
    for i in 0..32 {
        assert(inputs.webauthn.authenticator_data.storage()[i] == rp_id_hash[i]);
    }

    webauthn::verify_signature(
        inputs.webauthn.public_key_x,
        inputs.webauthn.public_key_y,
        inputs.webauthn.signature,
        inputs.webauthn.client_data_json,
        inputs.webauthn.authenticator_data,
        challenge,
        inputs.webauthn.challenge_index,
    );

    assert_lt(inputs.passkey_slot_index as Field, NUM_KEYS as Field);
    let public_key_x_limbs = p256_be_bytes_to_limbs(inputs.webauthn.public_key_x);
    let public_key_y_limbs = p256_be_bytes_to_limbs(inputs.webauthn.public_key_y);
    let expected_slot_commitment = passkey_slot_commitment(public_key_x_limbs, public_key_y_limbs);
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
