use alloy::primitives::U256;
use ark_bn254::Fr;
use semaphore_rs_hasher::Hasher;
use semaphore_rs_storage::MmapVec;
use semaphore_rs_trees::cascading::CascadingMerkleTree;
use thiserror::Error;

pub mod cached_tree;
pub mod state;
pub mod versioned;

pub use state::TreeState;
pub use versioned::VersionedTreeState;

use crate::db::WorldIdRegistryEventId;

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
    #[error("simulate_root computation did not produce a root — this is a bug")]
    SimulationMissingRoot,
    #[error(transparent)]
    Db(#[from] crate::db::DBError),
}

/// A tree that can accept leaf updates tied to an event ID.
///
/// Implemented by both [`TreeState`] (which ignores the event ID) and
/// [`VersionedTreeState`] (which records the event ID for rollback/pruning).
#[allow(async_fn_in_trait)]
pub trait TreeApplier {
    async fn apply_leaf(
        &self,
        leaf_index: usize,
        value: U256,
        event_id: WorldIdRegistryEventId,
    ) -> TreeResult<()>;
}

impl TreeApplier for TreeState {
    async fn apply_leaf(
        &self,
        leaf_index: usize,
        value: U256,
        _event_id: WorldIdRegistryEventId,
    ) -> TreeResult<()> {
        self.set_leaf_at_index(leaf_index, value).await
    }
}

impl TreeApplier for VersionedTreeState {
    async fn apply_leaf(
        &self,
        leaf_index: usize,
        value: U256,
        event_id: WorldIdRegistryEventId,
    ) -> TreeResult<()> {
        self.set_leaf_at_index(leaf_index, value, event_id).await
    }
}

/// Extract `(leaf_index, commitment)` from a `RegistryEvent`.
///
/// Returns `None` for `RootRecorded` events which carry no leaf data.
pub fn extract_leaf_commitment(
    event: &crate::blockchain::RegistryEvent,
) -> Option<(u64, U256)> {
    use crate::blockchain::RegistryEvent;

    match event {
        RegistryEvent::AccountCreated(ev) => Some((ev.leaf_index, ev.offchain_signer_commitment)),
        RegistryEvent::AccountUpdated(ev) => {
            Some((ev.leaf_index, ev.new_offchain_signer_commitment))
        }
        RegistryEvent::AuthenticatorInserted(ev) => {
            Some((ev.leaf_index, ev.new_offchain_signer_commitment))
        }
        RegistryEvent::AuthenticatorRemoved(ev) => {
            Some((ev.leaf_index, ev.new_offchain_signer_commitment))
        }
        RegistryEvent::AccountRecovered(ev) => {
            Some((ev.leaf_index, ev.new_offchain_signer_commitment))
        }
        RegistryEvent::RootRecorded(_) => None,
    }
}

/// Apply a single [`crate::blockchain::RegistryEvent`] to a tree.
///
/// Returns `Ok(true)` when a leaf was updated, `Ok(false)` for events that
/// carry no leaf data (e.g. `RootRecorded`).
pub async fn apply_event_to_tree(
    tree: &impl TreeApplier,
    event: &crate::blockchain::BlockchainEvent<crate::blockchain::RegistryEvent>,
) -> TreeResult<bool> {
    let Some((leaf_index, commitment)) = extract_leaf_commitment(&event.details) else {
        return Ok(false);
    };

    let event_id = WorldIdRegistryEventId {
        block_number: event.block_number,
        log_index: event.log_index,
    };

    tree.apply_leaf(leaf_index as usize, commitment, event_id)
        .await?;

    Ok(true)
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
