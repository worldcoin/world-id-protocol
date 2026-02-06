use std::sync::LazyLock;

use alloy::primitives::U256;
use ark_bn254::Fr;
use semaphore_rs_hasher::Hasher;
pub use semaphore_rs_trees::lazy::LazyMerkleTree as MerkleTree;
use semaphore_rs_trees::lazy::Canonical;
use thiserror::Error;
use tokio::sync::RwLock;
use world_id_primitives::TREE_DEPTH;

pub mod cached_tree;
pub mod state;

pub use state::TreeState;

pub type TreeResult<T> = Result<T, TreeError>;

#[derive(Debug, Error)]
pub enum TreeError {
    #[error("leaf index {leaf_index} out of range for tree depth {tree_depth}")]
    LeafIndexOutOfRange {
        leaf_index: usize,
        tree_depth: usize,
    },
    #[error("account index cannot be zero")]
    ZeroLeafIndex,
    #[error("invalid cache file path")]
    InvalidCacheFilePath,
    #[error("failed to restore tree from cache: {0}")]
    CacheRestore(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to create mmap tree: {0}")]
    CacheCreate(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("root mismatch - actual: {actual}, expected: {expected}")]
    RootMismatch { actual: String, expected: String },
    #[error("restored root not found in DB: {root}")]
    StaleCache { root: String },
    #[error(transparent)]
    Db(#[from] crate::db::DBError),
}

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
