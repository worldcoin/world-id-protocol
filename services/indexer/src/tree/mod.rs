use std::sync::LazyLock;

use alloy::primitives::U256;
use ark_bn254::Fr;
use semaphore_rs_hasher::Hasher;
pub use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use thiserror::Error;
use tokio::sync::RwLock;
pub use world_id_primitives::TREE_DEPTH;

pub mod builder;
pub mod initializer;
pub mod metadata;

#[cfg(test)]
mod tests;

pub use initializer::TreeInitializer;

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
    #[error("metadata file does not exist: {path}")]
    MetadataMissing { path: std::path::PathBuf },
    #[error("failed to read metadata file: {path}")]
    MetadataRead {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse metadata file: {path}")]
    MetadataParse {
        path: std::path::PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize metadata")]
    MetadataSerialize(#[source] serde_json::Error),
    #[error("failed to write metadata file: {path}")]
    MetadataWrite {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to rename metadata file: {from} -> {to}")]
    MetadataRename {
        from: std::path::PathBuf,
        to: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("root mismatch - actual: {actual}, expected: {expected}")]
    RootMismatch { actual: String, expected: String },
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

pub async fn set_leaf_at_index(leaf_index: usize, value: U256) -> TreeResult<()> {
    let capacity = tree_capacity().await;
    if leaf_index >= capacity {
        let depth = get_tree_depth().await;
        return Err(TreeError::LeafIndexOutOfRange {
            leaf_index,
            tree_depth: depth,
        });
    }

    let mut tree = GLOBAL_TREE.write().await;
    take_mut::take(&mut *tree, |tree| {
        tree.update_with_mutation(leaf_index, &value)
    });
    Ok(())
}

pub async fn update_tree_with_commitment(leaf_index: u64, new_commitment: U256) -> TreeResult<()> {
    if leaf_index == 0 {
        return Err(TreeError::ZeroLeafIndex);
    }
    let leaf_index = leaf_index as usize;
    set_leaf_at_index(leaf_index, new_commitment).await?;
    Ok(())
}
