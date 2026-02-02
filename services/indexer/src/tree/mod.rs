use std::sync::LazyLock;

use alloy::primitives::U256;
use ark_bn254::Fr;
use semaphore_rs_hasher::Hasher;
pub use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use tokio::sync::RwLock;
pub use world_id_primitives::TREE_DEPTH;

pub mod cached_tree;

pub struct PoseidonHasher {}

impl Hasher for PoseidonHasher {
    type Hash = U256;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let left: Fr = left.try_into().unwrap();
        let right: Fr = right.try_into().unwrap();
        let mut input = [left, right];
        let feed_forward = input[0];
        poseidon2::bn254::t2::permutation_in_place(&mut input);
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

