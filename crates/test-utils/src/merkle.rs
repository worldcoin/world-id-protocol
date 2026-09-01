use ark_babyjubjub::Fq;
use world_id_primitives::{FieldElement, TREE_DEPTH, poseidon};

/// Builds the default-zero sibling path for index 1 and computes the Merkle root
/// after inserting the provided `leaf` at that index, using Poseidon2 T2 compress.
pub fn first_leaf_merkle_path(leaf: Fq) -> ([FieldElement; TREE_DEPTH], FieldElement) {
    let mut siblings = [FieldElement::ZERO; TREE_DEPTH];
    let mut zero = FieldElement::ZERO;
    for sibling in siblings.iter_mut() {
        *sibling = zero;
        zero = poseidon::compress(zero, zero);
    }

    let mut current = poseidon::compress(siblings[0], leaf.into());
    // For the remaining levels, continue hashing with current on the left
    for sibling in &siblings[1..] {
        current = poseidon::compress(current, *sibling);
    }

    (siblings, current)
}
