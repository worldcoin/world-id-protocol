use super::{constants::MERKLE_LEAF_DS, types::PublicKey};
use poseidon2::bn254::perm;

pub fn merkle_leaf<let NUM_KEYS: u32>(pk: [PublicKey; NUM_KEYS]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = MERKLE_LEAF_DS;

    for i in 0..NUM_KEYS {
        inputs[i * 2 + 1] = pk[i].x;
        inputs[i * 2 + 2] = pk[i].y;
    }

    let hash_state = perm::x5_16(inputs);
    hash_state[1]
}

pub fn compute_merkle_root_poseidon2<let N: u32>(
    leaf: Field,
    depth: Field,
    index: Field,
    hashpath: [Field; N],
) -> Field {
    let mut current = leaf;
    // we check index < 2^32 to allow the below cast
    index.assert_max_bit_size::<32>();
    let mut idx = index as u32;
    // depth is public and checked outside of the circuit to be < 32 and < MAX_DEPTH
    // we check it anyways below since it actually produces more efficient constraints
    depth.assert_max_bit_size::<5>();
    let depth_u32 = depth as u32;
    assert(idx < (1 << depth_u32), "Index must be less than 2^depth");
    assert(depth == N as Field);

    for i in 0..N {
        if i < depth_u32 {
            let sibling = hashpath[i];
            let is_right = idx & 1;

            // Use branchless selection
            let is_right_field = is_right as Field;
            let diff = current - sibling;
            let left = sibling + (diff * (1 - is_right_field));
            let right = sibling + (diff * is_right_field);

            let hash_state = perm::x5_2([left, right]);
            current = hash_state[0] + left;

            idx >>= 1;
        }
    }

    current
}

#[test]
fn test_merkle_leaf_deterministic() {
    let pk = [PublicKey { x: 1, y: 2 }, PublicKey { x: 3, y: 4 }, PublicKey { x: 5, y: 6 }];
    let leaf1 = merkle_leaf(pk);
    let leaf2 = merkle_leaf(pk);
    assert_eq(leaf1, leaf2);
}

#[test]
fn test_merkle_leaf_different_keys() {
    let pk_a = [PublicKey { x: 1, y: 2 }];
    let pk_b = [PublicKey { x: 3, y: 4 }];
    assert(merkle_leaf(pk_a) != merkle_leaf(pk_b));
}

#[test]
fn test_compute_merkle_root_left_child() {
    let leaf: Field = 123;
    let sibling: Field = 456;

    // index=0: leaf is the left child
    let hash_state = perm::x5_2([leaf, sibling]);
    let expected_root = hash_state[0] + leaf;

    let computed = compute_merkle_root_poseidon2(leaf, 1, 0, [sibling]);
    assert_eq(computed, expected_root);
}

#[test]
fn test_compute_merkle_root_right_child() {
    let leaf: Field = 123;
    let sibling: Field = 456;

    // index=1: leaf is the right child
    let hash_state = perm::x5_2([sibling, leaf]);
    let expected_root = hash_state[0] + sibling;

    let computed = compute_merkle_root_poseidon2(leaf, 1, 1, [sibling]);
    assert_eq(computed, expected_root);
}

#[test]
fn test_compute_merkle_root_depth_2() {
    let leaf: Field = 10;
    let sib0: Field = 20;
    let sib1: Field = 30;

    // index=0 (binary 00): leaf is left at both levels
    // Level 0: hash(leaf, sib0)
    let h0 = perm::x5_2([leaf, sib0]);
    let level0 = h0[0] + leaf;
    // Level 1: hash(level0, sib1)
    let h1 = perm::x5_2([level0, sib1]);
    let expected_root = h1[0] + level0;

    let computed = compute_merkle_root_poseidon2(leaf, 2, 0, [sib0, sib1]);
    assert_eq(computed, expected_root);
}

#[test]
fn test_compute_merkle_root_depth_2_index_3() {
    let leaf: Field = 10;
    let sib0: Field = 20;
    let sib1: Field = 30;

    // index=3 (binary 11): leaf is right at both levels
    // Level 0: hash(sib0, leaf)
    let h0 = perm::x5_2([sib0, leaf]);
    let level0 = h0[0] + sib0;
    // Level 1: hash(sib1, level0)
    let h1 = perm::x5_2([sib1, level0]);
    let expected_root = h1[0] + sib1;

    let computed = compute_merkle_root_poseidon2(leaf, 2, 3, [sib0, sib1]);
    assert_eq(computed, expected_root);
}

#[test(should_fail_with = "Index must be less than 2^depth")]
fn test_compute_merkle_root_index_out_of_range() {
    // index=2 with depth=1 means max valid index is 1
    let _ = compute_merkle_root_poseidon2(123, 1, 2, [456]);
}

#[test(should_fail)]
fn test_compute_merkle_root_rejects_exceeding_depth() {
    // depth=31 must be rejected because it exceeds the MAX_DEPTH size.
    let siblings = [0; 30];
    let _ = compute_merkle_root_poseidon2(0, 31, 0, siblings);
}
