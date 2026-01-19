use std::sync::LazyLock;

use alloy::primitives::U256;
use ark_bn254::Fr;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T2_PARAMS};
use semaphore_rs_hasher::Hasher;
pub use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use tokio::sync::RwLock;
pub use world_id_primitives::TREE_DEPTH;

pub mod builder;
pub mod initializer;
pub mod metadata;

pub use initializer::TreeInitializer;

// Poseidon2 hasher singleton
static POSEIDON_HASHER: LazyLock<Poseidon2<Fr, 2, 5>> =
    LazyLock::new(|| Poseidon2::new(&POSEIDON2_BN254_T2_PARAMS));

pub struct PoseidonHasher {}

impl Hasher for PoseidonHasher {
    type Hash = U256;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let left: Fr = left.try_into().unwrap();
        let right: Fr = right.try_into().unwrap();
        let mut input = [left, right];
        let feed_forward = input[0];
        POSEIDON_HASHER.permutation_in_place(&mut input);
        input[0] += feed_forward;
        input[0].into()
    }
}

pub fn tree_capacity() -> usize {
    1usize << TREE_DEPTH
}

// Global Merkle tree (singleton). Protected by an async RwLock for concurrent reads.
pub static GLOBAL_TREE: LazyLock<RwLock<MerkleTree<PoseidonHasher, Canonical>>> =
    LazyLock::new(|| RwLock::new(MerkleTree::<PoseidonHasher>::new(TREE_DEPTH, U256::ZERO)));

pub async fn set_leaf_at_index(leaf_index: usize, value: U256) -> anyhow::Result<()> {
    if leaf_index >= tree_capacity() {
        anyhow::bail!("leaf index {leaf_index} out of range for tree depth {TREE_DEPTH}");
    }

    let mut tree = GLOBAL_TREE.write().await;
    take_mut::take(&mut *tree, |tree| {
        tree.update_with_mutation(leaf_index, &value)
    });
    Ok(())
}

pub async fn update_tree_with_commitment(
    leaf_index: U256,
    new_commitment: U256,
) -> anyhow::Result<()> {
    if leaf_index == U256::ZERO {
        anyhow::bail!("account index cannot be zero");
    }
    let leaf_index = leaf_index.as_limbs()[0] as usize;
    set_leaf_at_index(leaf_index, new_commitment).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use semaphore_rs_trees::Branch;

    use super::*;

    #[test]
    fn test_poseidon2_merkle_tree() {
        use alloy::uint;

        let tree = MerkleTree::<PoseidonHasher>::new(10, U256::ZERO);
        let proof = tree.proof(0);
        let proof = proof.0.iter().collect::<Vec<_>>();
        assert!(
            *proof[1]
                == Branch::Left(uint!(
                    15621590199821056450610068202457788725601603091791048810523422053872049975191_U256
                ))
        );
    }
}
