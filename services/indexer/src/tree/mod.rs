use alloy::primitives::U256;
use ark_bn254::Fr;
use semaphore_rs_hasher::Hasher;
use semaphore_rs_storage::MmapVec;
use semaphore_rs_trees::cascading::CascadingMerkleTree;
use thiserror::Error;

pub mod cached_tree;
pub mod state;

pub use state::TreeState;

pub type TreeResult<T> = Result<T, TreeError>;

pub type MerkleTree = CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>;

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
