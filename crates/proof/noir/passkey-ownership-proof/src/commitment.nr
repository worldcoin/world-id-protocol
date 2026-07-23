use super::constants::{DS_MIXED_AUTH_SET, DS_PASSKEY_SLOT, NUM_KEYS, P256_LIMBS};
use poseidon2::bn254::permutation;

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

    let hash_state = permutation::t16(inputs);
    hash_state[1]
}

pub fn mixed_authenticator_set_commitment(slot_commitments: [Field; NUM_KEYS]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = DS_MIXED_AUTH_SET;

    for i in 0..NUM_KEYS {
        inputs[i + 1] = slot_commitments[i];
    }

    let hash_state = permutation::t16(inputs);
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

#[test]
fn test_poseidon2_t16_matches_legacy_vector() {
    assert(
        permutation::t16([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            == [
                0x0fc2e6b758f493969e1d860f9a44ee3bdffdf796f382aa4ffb16fa4e9bcc333f,
                0x0c118155a0dfeca3f91faf14a350511228ac33743be91249c6e0b3a635a50de4,
                0x1a02b3a6571f22bb6392322d3f9f5de145b4f00bdf483072ce6188c30ba0f83d,
                0x26631df6b2522ecde57413cd680ed590ded356e1c680f865f45be8eb960d1e06,
                0x250ac4dfed40dc37bac9abe46f7bff3a80481d52a157ac80a1e5d39a5ed60e18,
                0x17160980d8e7d9cb31addaf294cf047768bffd9fe433e8903b4ed262ee913f5b,
                0x1d708a9f0995c2e0cd2f55e5dc795126f7191a0eb934ac8172bf54e520361ff6,
                0x20721a18915e96e37e12c9697427f34d6a366787ea94ea65565c36813a0d77a3,
                0x08671a9e58105eed9ac673249dcf22f08f098e3c6eb28f9eaa55d67d755972d0,
                0x01e879484303c6d057128fbcc3a4222c779a62d3666df65d4e0b64c8031d7cc4,
                0x239e2ce87955ebe19aaad000b38725b729f51175ab7d688f15d997edf0e3b7fc,
                0x06be612f42b3ebdbade3fe199338c9118eb6b5fb760bda96e45443f130a8b2de,
                0x11b2c04b4eb9e4844e5ddbb19b56059a815ed5d69405ba51786961235d5f073c,
                0x006da33e2d57616c0ffc855b48d225a1237c3d80fc7e6b6e73b74e162b85c8a8,
                0x0ef50c2615882523c6c73a69b4371332a066b2dc4b9630f186db47e3bfca88c8,
                0x0e2ceb1f8fde5f80be1f41bd239fabdc2f6133a6a98920a55c42891c3a925152,
            ],
    );
}
