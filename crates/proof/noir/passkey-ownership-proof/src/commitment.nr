use super::constants::{DS_MIXED_AUTH_SET, DS_PASSKEY_SLOT, NUM_KEYS, P256_LIMBS};
use poseidon2::bn254::perm;

pub fn passkey_slot_commitment(
    public_key_x_limbs: [Field; P256_LIMBS],
    public_key_y_limbs: [Field; P256_LIMBS],
) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = DS_PASSKEY_SLOT;

    for i in 0..P256_LIMBS {
        public_key_x_limbs[i].assert_max_bit_size::<120>();
        public_key_y_limbs[i].assert_max_bit_size::<120>();
        inputs[i + 1] = public_key_x_limbs[i];
        inputs[i + 1 + P256_LIMBS] = public_key_y_limbs[i];
    }

    let hash_state = perm::x5_16(inputs);
    hash_state[1]
}

pub fn mixed_authenticator_set_commitment(slot_commitments: [Field; NUM_KEYS]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = DS_MIXED_AUTH_SET;

    for i in 0..NUM_KEYS {
        inputs[i + 1] = slot_commitments[i];
    }

    let hash_state = perm::x5_16(inputs);
    hash_state[1]
}

#[test]
fn test_slot_commitment_changes_with_key() {
    let left = passkey_slot_commitment([1, 2, 3], [4, 5, 6]);
    let right = passkey_slot_commitment([1, 2, 7], [4, 5, 6]);
    assert(left != right);
}

#[test]
fn test_account_commitment_changes_with_slot() {
    let left = mixed_authenticator_set_commitment([1, 0, 0, 0, 0, 0, 0]);
    let right = mixed_authenticator_set_commitment([0, 1, 0, 0, 0, 0, 0]);
    assert(left != right);
}
