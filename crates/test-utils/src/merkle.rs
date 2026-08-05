use ark_babyjubjub::Fq;
use ark_ff::AdditiveGroup;
use world_id_primitives::{FieldElement, TREE_DEPTH};

/// Builds the default-zero sibling path for index 1 and computes the Merkle root
/// after inserting the provided `leaf` at that index, using Poseidon2 T2 compress.
pub fn first_leaf_merkle_path(leaf: Fq) -> ([FieldElement; TREE_DEPTH], FieldElement) {
    let mut siblings = [FieldElement::ZERO; TREE_DEPTH];
    let mut zero = Fq::ZERO;
    for sibling in siblings.iter_mut() {
        *sibling = zero.into();
        zero = poseidon2_compress(zero, zero);
    }

    let mut current = poseidon2_compress(*siblings[0], leaf);
    // For the remaining levels, continue hashing with current on the left
    for sibling in &siblings[1..] {
        current = poseidon2_compress(current, **sibling);
    }

    (siblings, current.into())
}

/// Poseidon2 "compress" for a pair of field elements (left, right).
fn poseidon2_compress(left: Fq, right: Fq) -> Fq {
    let mut state = poseidon2::bn254::t2::permutation(&[left, right]);
    state[0] += left;
    state[0]
}
