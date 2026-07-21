use super::constants::MAX_DEPTH;
use poseidon2::bn254::perm;

pub fn compute_merkle_root_poseidon2(
    leaf: Field,
    index: u32,
    hashpath: [Field; MAX_DEPTH],
) -> Field {
    let mut current = leaf;
    let mut idx = index;

    for i in 0..MAX_DEPTH {
        let sibling = hashpath[i];
        let is_right = idx & 1;

        let is_right_field = is_right as Field;
        let diff = current - sibling;
        let left = sibling + (diff * (1 - is_right_field));
        let right = sibling + (diff * is_right_field);

        let hash_state = perm::x5_2([left, right]);
        current = hash_state[0] + left;

        idx >>= 1;
    }

    current
}

#[test]
fn test_compute_merkle_root_left_child() {
    let mut siblings = [0; MAX_DEPTH];
    siblings[0] = 456;

    let hash_state = perm::x5_2([123, 456]);
    let first = hash_state[0] + 123;

    let mut expected = first;
    for i in 1..MAX_DEPTH {
        let next = perm::x5_2([expected, siblings[i]]);
        expected = next[0] + expected;
    }

    let computed = compute_merkle_root_poseidon2(123, 0, siblings);
    assert_eq(computed, expected);
}
