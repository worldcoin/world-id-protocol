// `WorldIDRegistry` Merkle inclusion at the WIP-100 fixed depth of 30.
//
// Same leaf and node hashing as `ownership-proof/src/merkle_proof.nr`, with the
// depth baked in: WIP-100 fixes it at 30 and requires `0 < leaf_index < 2^30`,
// so this circuit takes no depth input.
use super::{constants::{MERKLE_DEPTH, MERKLE_LEAF_DS, NUM_KEYS}, types::PublicKey};
use poseidon2::bn254::perm;

/// The `WorldIDRegistry` leaf: the authenticator key set commitment
/// `H_16(MERKLE_LEAF_DS; user_pk[0].x, user_pk[0].y, ..., user_pk[6].x, user_pk[6].y)`,
/// all `NUM_KEYS` slots in order (inactive slots included as the identity),
/// state index 15 zero.
pub fn key_set_commitment(user_pk: [PublicKey; NUM_KEYS]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = MERKLE_LEAF_DS;
    for i in 0..NUM_KEYS {
        inputs[i * 2 + 1] = user_pk[i].x;
        inputs[i * 2 + 2] = user_pk[i].y;
    }
    perm::x5_16(inputs)[1]
}

/// Recomputes the root from `leaf` at position `leaf_index` using `siblings`.
///
/// Constrains `0 < leaf_index < 2^30` per WIP-100.
pub fn compute_merkle_root(
    leaf: Field,
    leaf_index: Field,
    siblings: [Field; MERKLE_DEPTH],
) -> Field {
    assert(leaf_index != 0, "leaf_index must not be zero");
    leaf_index.assert_max_bit_size::<30>();
    let mut idx = leaf_index as u32;

    let mut current = leaf;
    for i in 0..MERKLE_DEPTH {
        let sibling = siblings[i];
        let is_right = (idx & 1) as Field;

        // Branchless child ordering
        let diff = current - sibling;
        let left = sibling + (diff * (1 - is_right));
        let right = sibling + (diff * is_right);

        let hash_state = perm::x5_2([left, right]);
        current = hash_state[0] + left;

        idx >>= 1;
    }
    current
}

mod tests {
    use crate::constants::MERKLE_DEPTH;
    use crate::types::PublicKey;
    use super::{compute_merkle_root, key_set_commitment};
    use poseidon2::bn254::perm;

    #[test]
    fn test_compute_merkle_root_matches_manual_path() {
        let leaf: Field = 123;
        let mut siblings: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
        siblings[0] = 456;

        // index 1: leaf is the right child at level 0, left above.
        let h0 = perm::x5_2([siblings[0], leaf]);
        let mut expected = h0[0] + siblings[0];
        for i in 1..MERKLE_DEPTH {
            let h = perm::x5_2([expected, siblings[i]]);
            expected = h[0] + expected;
        }

        assert_eq(compute_merkle_root(leaf, 1, siblings), expected);
    }

    #[test(should_fail_with = "leaf_index must not be zero")]
    fn test_compute_merkle_root_rejects_zero_index() {
        let _ = compute_merkle_root(123, 0, [0; MERKLE_DEPTH]);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_compute_merkle_root_rejects_index_beyond_depth() {
        let _ = compute_merkle_root(123, 0x40000000, [0; MERKLE_DEPTH]);
    }

    #[test]
    fn test_key_set_commitment_binds_every_slot() {
        let mut a = [PublicKey { x: 0, y: 1 }; 7];
        a[0] = PublicKey { x: 1, y: 2 };
        let mut b = a;
        b[6] = PublicKey { x: 3, y: 4 };
        assert(key_set_commitment(a) != key_set_commitment(b));
    }
}
