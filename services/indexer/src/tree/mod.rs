use alloy::primitives::U256;
use ark_bn254::Fr;
use semaphore_rs_hasher::Hasher;
use semaphore_rs_storage::MmapVec;
use semaphore_rs_trees::cascading::CascadingMerkleTree;
use thiserror::Error;
use world_id_primitives::poseidon;

pub mod cached_tree;
pub mod checkpoint;
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
    #[error(
        "cannot rollback versioned tree to event {target:?}: history has been pruned past this point"
    )]
    RollbackHistoryPruned { target: WorldIdRegistryEventId },
    #[error(transparent)]
    Db(#[from] crate::db::DBError),
}

impl TreeError {
    /// Whether this error means the on-disk tree cache/checkpoint is itself
    /// invalid (corrupt, unreadable, or stale relative to the DB) — in which
    /// case deleting it and rebuilding from the DB in-process is the correct
    /// recovery.
    ///
    /// `false` means the cache is probably fine and the failure came from
    /// somewhere else (e.g. the database) — deleting the cache would not fix
    /// it and could destroy a perfectly good cache, so the caller should
    /// leave the cache untouched and propagate the error instead.
    ///
    /// `TreeError`'s own variants are matched exhaustively (no wildcard) so
    /// adding one forces an explicit classification decision here — whoever
    /// adds a `TreeError` variant is already working on tree-restore
    /// semantics, so that's a cheap, correctly-targeted forcing function.
    ///
    /// `DBError` is a general-purpose error type used far beyond tree
    /// restore, so its variants are matched with an explicit default instead
    /// of exhaustively: forcing every future, unrelated `DBError` addition to
    /// be classified here would mostly land on people with no context on
    /// tree-restore recovery. Only the two known event-log decode failures
    /// are special-cased; anything else (including future variants) falls
    /// back to "not cache-invalidating," the safe direction — the failure
    /// mode of under-classifying is a missed opportunity to self-heal via
    /// rebuild, not a destroyed cache.
    fn invalidates_cache(&self) -> bool {
        match self {
            TreeError::CacheRestore(_)
            | TreeError::CacheCreate(_)
            | TreeError::InvalidCacheFilePath
            | TreeError::RootMismatch { .. }
            | TreeError::StaleCache { .. } => true,
            TreeError::LeafIndexOutOfRange { .. } => false,
            TreeError::ZeroLeafIndex => false,
            TreeError::SimulationMissingRoot => false,
            TreeError::RollbackHistoryPruned { .. } => false,
            TreeError::Db(inner) => match inner {
                // Event-log decode failures: the mmap cache is fine, but
                // replaying events hit a row that won't decode. A fallback
                // rebuild reads the `accounts` snapshot instead (written in
                // the same DB transaction as the offending row) and bypasses
                // the bad row entirely, so it will very likely succeed where
                // a bare restart would just hit the same row again.
                crate::db::DBError::UnknownEventType(_)
                | crate::db::DBError::MissingEventField { .. }
                | crate::db::DBError::InvalidEventField { .. } => true,
                // Sqlx/Migrate and anything added later: treat as infra —
                // a rebuild needs the DB too, so it would fail the same way.
                _ => false,
            },
        }
    }
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
pub fn extract_leaf_commitment(event: &crate::blockchain::RegistryEvent) -> Option<(u64, U256)> {
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
        (*poseidon::compress(left.into(), right.into())).into()
    }
}

#[cfg(test)]
mod invalidates_cache_tests {
    use super::*;
    use crate::db::DBError;

    fn boxed_err() -> Box<dyn std::error::Error + Send + Sync> {
        "boom".into()
    }

    #[test]
    fn cache_restore_invalidates_cache() {
        assert!(TreeError::CacheRestore(boxed_err()).invalidates_cache());
    }

    #[test]
    fn cache_create_invalidates_cache() {
        assert!(TreeError::CacheCreate(boxed_err()).invalidates_cache());
    }

    #[test]
    fn invalid_cache_file_path_invalidates_cache() {
        assert!(TreeError::InvalidCacheFilePath.invalidates_cache());
    }

    #[test]
    fn root_mismatch_invalidates_cache() {
        assert!(
            TreeError::RootMismatch {
                actual: "0x1".to_string(),
                expected: "0x2".to_string(),
            }
            .invalidates_cache()
        );
    }

    #[test]
    fn stale_cache_invalidates_cache() {
        assert!(
            TreeError::StaleCache {
                root: "0x1".to_string(),
            }
            .invalidates_cache()
        );
    }

    #[test]
    fn leaf_index_out_of_range_does_not_invalidate_cache() {
        assert!(
            !TreeError::LeafIndexOutOfRange {
                leaf_index: 1,
                tree_depth: 2,
            }
            .invalidates_cache()
        );
    }

    #[test]
    fn zero_leaf_index_does_not_invalidate_cache() {
        assert!(!TreeError::ZeroLeafIndex.invalidates_cache());
    }

    #[test]
    fn simulation_missing_root_does_not_invalidate_cache() {
        assert!(!TreeError::SimulationMissingRoot.invalidates_cache());
    }

    #[test]
    fn rollback_history_pruned_does_not_invalidate_cache() {
        assert!(
            !TreeError::RollbackHistoryPruned {
                target: WorldIdRegistryEventId {
                    block_number: 0,
                    log_index: 0,
                },
            }
            .invalidates_cache()
        );
    }

    #[test]
    fn db_unknown_event_type_invalidates_cache() {
        assert!(TreeError::Db(DBError::UnknownEventType("bogus".to_string())).invalidates_cache());
    }

    #[test]
    fn db_missing_event_field_invalidates_cache() {
        assert!(
            TreeError::Db(DBError::MissingEventField {
                field: "root".to_string(),
            })
            .invalidates_cache()
        );
    }

    #[test]
    fn db_invalid_event_field_invalidates_cache() {
        assert!(
            TreeError::Db(DBError::InvalidEventField {
                field: "root".to_string(),
                reason: "not hex".to_string(),
            })
            .invalidates_cache()
        );
    }

    #[test]
    fn db_sqlx_error_does_not_invalidate_cache() {
        assert!(!TreeError::Db(DBError::Sqlx(sqlx::Error::RowNotFound)).invalidates_cache());
    }

    #[test]
    fn db_migrate_error_does_not_invalidate_cache() {
        assert!(
            !TreeError::Db(DBError::Migrate(
                sqlx::migrate::MigrateError::VersionMissing(1)
            ))
            .invalidates_cache()
        );
    }
}
