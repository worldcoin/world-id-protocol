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

#[cfg(test)]
mod tests;

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

// Store the configured tree depth (set during initialization)
static CONFIGURED_TREE_DEPTH: LazyLock<RwLock<usize>> = LazyLock::new(|| RwLock::new(TREE_DEPTH));

pub async fn set_tree_depth(depth: usize) {
    let mut configured_depth = CONFIGURED_TREE_DEPTH.write().await;
    *configured_depth = depth;
}

pub async fn get_tree_depth() -> usize {
    *CONFIGURED_TREE_DEPTH.read().await
}

pub async fn tree_capacity() -> usize {
    let depth = get_tree_depth().await;
    1usize << depth
}

// Global Merkle tree (singleton). Protected by an async RwLock for concurrent reads.
// Initial tree uses TREE_DEPTH but will be replaced during initialization with configured depth
pub static GLOBAL_TREE: LazyLock<RwLock<MerkleTree<PoseidonHasher, Canonical>>> =
    LazyLock::new(|| RwLock::new(MerkleTree::<PoseidonHasher>::new(TREE_DEPTH, U256::ZERO)));

pub async fn set_leaf_at_index(leaf_index: usize, value: U256) -> anyhow::Result<()> {
    let capacity = tree_capacity().await;
    if leaf_index >= capacity {
        let depth = get_tree_depth().await;
        anyhow::bail!("leaf index {leaf_index} out of range for tree depth {depth}");
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
