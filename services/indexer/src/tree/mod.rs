use alloy::primitives::U256;
use ark_bn254::Fr;
use semaphore_rs_hasher::Hasher;
pub use semaphore_rs_trees::lazy::LazyMerkleTree as MerkleTree;
use thiserror::Error;

pub mod builder;
pub mod initializer;
pub mod metadata;
pub mod state;

#[cfg(test)]
mod tests;

pub use initializer::TreeInitializer;
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
