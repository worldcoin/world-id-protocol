use ark_babyjubjub::Fq;
use ark_ff::AdditiveGroup;
use oprf_world_types::TREE_DEPTH;
use poseidon2::Poseidon2;
use world_id_primitives::FieldElement;

/// Builds the default-zero sibling path for index 0 and computes the Merkle root
/// after inserting the provided `leaf` at that index, using Poseidon2 T2 compress.
pub fn first_leaf_merkle_path(leaf: Fq) -> ([FieldElement; TREE_DEPTH], FieldElement) {
    let poseidon2_2: Poseidon2<Fq, 2, 5> = Poseidon2::default();
    let mut siblings = [FieldElement::ZERO; TREE_DEPTH];
    let mut zero = Fq::ZERO;
    for sibling in siblings.iter_mut() {
        *sibling = zero.into();
        zero = poseidon2_compress(&poseidon2_2, zero, zero);
    }

    let mut current = leaf;
    for sibling in siblings.iter() {
        current = poseidon2_compress(&poseidon2_2, current, **sibling);
    }

    (siblings, current.into())
}

/// Poseidon2 "compress" for a pair of field elements (left, right).
fn poseidon2_compress(poseidon2: &Poseidon2<Fq, 2, 5>, left: Fq, right: Fq) -> Fq {
    let mut state = poseidon2.permutation(&[left, right]);
    state[0] += left;
    state[0]
}
