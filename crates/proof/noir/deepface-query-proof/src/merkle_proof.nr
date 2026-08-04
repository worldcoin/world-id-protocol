use poseidon2::bn254::perm;

/// Recomputes a binary Merkle root in Poseidon2 compression mode.
///
/// Duplicated verbatim from `noir/ownership-proof/src/merkle_proof.nr`: that package is a
/// `bin`, so its modules cannot be imported. Both must stay in sync with
/// `circom/merkle_tree/binary_merkle_root.circom`, which is why extracting a shared Noir
/// lib is tracked as a follow-up.
///
/// `merkle_leaf` is not duplicated -- the billing tree's leaf is the session id
/// commitment, not a hashed authenticator key set.
pub(crate) fn compute_merkle_root_poseidon2<let N: u32>(
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
    assert(depth as u32 <= N);

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
fn test_compute_merkle_root_left_child() {
    let leaf: Field = 123;
    let sibling: Field = 456;

    // index=0: leaf is the left child
    let hash_state = perm::x5_2([leaf, sibling]);
    let expected_root = hash_state[0] + leaf;

    assert_eq(compute_merkle_root_poseidon2(leaf, 1, 0, [sibling]), expected_root);
}

#[test]
fn test_compute_merkle_root_right_child() {
    let leaf: Field = 123;
    let sibling: Field = 456;

    // index=1: leaf is the right child
    let hash_state = perm::x5_2([sibling, leaf]);
    let expected_root = hash_state[0] + sibling;

    assert_eq(compute_merkle_root_poseidon2(leaf, 1, 1, [sibling]), expected_root);
}

#[test(should_fail_with = "Index must be less than 2^depth")]
fn test_compute_merkle_root_index_out_of_range() {
    let _ = compute_merkle_root_poseidon2(123, 1, 2, [456]);
}
