use std::path::Path;

use alloy::primitives::U256;
use futures_util::TryStreamExt as _;
use semaphore_rs_storage::MmapVec;
use tracing::{info, instrument};

use super::{TreeError, TreeResult, TreeState};
use crate::{
    batch::{Batch, BatchHeader, Persisted},
    db::{DB, IsolationLevel, WorldIdRegistryEventId},
    tree::MerkleTree,
};

// =============================================================================
// Public API
// =============================================================================

/// Unified tree initialization.
///
/// 1. If mmap file exists → load it, validate root against sync batches, catch up
/// 2. If mmap missing or validation fails → full rebuild from sync batches
///
/// Returns a `TreeState` with the batch cursor set so `sync_from_db()` can
/// pick up future batches incrementally.
///
/// # Safety
///
/// This function is marked unsafe because it performs memory-mapped file operations for the tree cache.
/// The caller must ensure that the cache file is not concurrently accessed or modified
/// by other processes while the tree is using it.
#[instrument(level = "info", skip_all, fields(tree_depth))]
pub async unsafe fn init_tree(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<TreeState> {
    let (tree, last_event_id, last_batch_id) = if cache_path.exists() {
        match try_restore(db, cache_path, tree_depth).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(?e, "restore failed, deleting cache file");
                let _ = std::fs::remove_file(cache_path);
                return Err(e);
            }
        }
    } else {
        info!("no cache file, building from sync batches");
        build_from_sync_log_with_cache(db, cache_path, tree_depth).await?
    };

    let tree_state = TreeState::new_with_batch_id(tree, tree_depth, last_event_id, last_batch_id);
    crate::metrics::set_tree_last_synced_block(last_event_id.block_number);
    crate::metrics::set_chain_processed_block(last_event_id.block_number);

    sync_from_db(db, &tree_state).await?;

    Ok(tree_state)
}

/// Incrementally sync the in-memory tree with sync batches committed to DB
/// since the last sync point. Batches are applied atomically and the cursor
/// advances only after the resulting root is validated.
///
/// Returns the number of leaf changes processed through verified batches.
#[instrument(level = "info", skip_all)]
pub async fn sync_from_db(db: &DB, tree_state: &TreeState) -> TreeResult<usize> {
    const BATCH_SIZE: u64 = 256;

    let started = std::time::Instant::now();
    let from = tree_state.last_batch_id().await;
    let mut cursor = from;
    let mut processed_count = 0usize;
    let mut last_verified_batch_id = from;

    // Paginated fetch of batches from the database.
    loop {
        let batches = db
            .sync_log()
            .get_batches(cursor, None, Some(BATCH_SIZE))
            .await?;

        if batches.is_empty() {
            break;
        }

        let at_end = (batches.len() as u64) < BATCH_SIZE;
        processed_count += apply_batches(tree_state, &batches, &mut last_verified_batch_id).await?;
        cursor = batches.last().map(|batch| batch.batch_id).unwrap_or(cursor);

        if at_end {
            break;
        }
    }

    let latency_ms = started.elapsed().as_millis() as f64;
    if processed_count == 0 {
        crate::metrics::record_tree_sync(0, latency_ms, 0);
        return Ok(0);
    }

    info!(
        processed_count,
        last_verified_batch_id, "synced tree from sync batches"
    );

    crate::metrics::record_tree_sync(processed_count, latency_ms, 0);

    Ok(processed_count)
}

// =============================================================================
// Private helpers
// =============================================================================

struct SyncLogSnapshot {
    max_batch_id: u64,
    checkpoint: Option<Persisted<BatchHeader>>,
    leaves: Vec<U256>,
    last_event_id: WorldIdRegistryEventId,
}

/// Try to restore from mmap cache and recover the batch cursor from the DB.
async fn try_restore(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<(MerkleTree, WorldIdRegistryEventId, u64)> {
    let tree = restore_from_cache(cache_path, tree_depth)?;
    let root = tree.root();

    info!(
        root = %format!("0x{:x}", root),
        "loaded mmap"
    );

    let last_batch_id = db
        .sync_log()
        .get_latest_batch_id_by_root(root)
        .await?
        .ok_or(TreeError::StaleCache {
            root: format!("0x{root:x}"),
        })?;

    let last_event_id = db
        .world_id_registry_events()
        .get_latest_id()
        .await?
        .unwrap_or_default();

    info!(last_batch_id, ?last_event_id, "restored tree from cache");

    Ok((tree, last_event_id, last_batch_id))
}

/// Restore tree from mmap file (no validation).
fn restore_from_cache(cache_path: &Path, tree_depth: usize) -> eyre::Result<MerkleTree> {
    let cache_path_str = cache_path.to_str().ok_or(TreeError::InvalidCacheFilePath)?;
    let storage = unsafe { MmapVec::<U256>::restore_from_path(cache_path_str)? };
    let tree = MerkleTree::restore(storage, tree_depth, &U256::ZERO)?;
    info!(
        cache_file = %cache_path.display(),
        root = %format!("0x{:x}", tree.root()),
        "Restored tree from cache"
    );

    Ok(tree)
}

/// Build tree from the sync batch projection with mmap backing.
#[instrument(level = "info", skip_all)]
async fn build_from_sync_log_with_cache(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<(MerkleTree, WorldIdRegistryEventId, u64)> {
    info!("Building tree from sync batches with mmap cache");

    if cache_path.exists() {
        std::fs::remove_file(cache_path)?;
    }

    let snapshot = load_sync_log_snapshot(db, tree_depth).await?;

    info!(
        len = snapshot.leaves.len(),
        max_batch_id = snapshot.max_batch_id,
        "Building Tree"
    );

    let cache_path_str = cache_path.to_str().ok_or(TreeError::InvalidCacheFilePath)?;
    let storage = unsafe { MmapVec::<U256>::create_from_path(cache_path_str)? };
    let tree = MerkleTree::new_with_leaves(storage, tree_depth, &U256::ZERO, &snapshot.leaves);

    if let Some(checkpoint) = &snapshot.checkpoint {
        verify_root(tree.root(), checkpoint.inner.expected_root)?;
    }

    info!(
        root = %format!("0x{:x}", tree.root()),
        "Tree built from sync batches with mmap cache"
    );

    Ok((
        tree,
        snapshot.last_event_id,
        snapshot
            .checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.batch_id)
            .unwrap_or(0),
    ))
}

async fn load_sync_log_snapshot(db: &DB, tree_depth: usize) -> TreeResult<SyncLogSnapshot> {
    let mut tx = db.transaction(IsolationLevel::RepeatableRead).await?;
    let max_batch_id = tx.sync_log().await?.get_max_batch_id().await?;
    let checkpoint = tx
        .sync_log()
        .await?
        .get_latest_batch_at(max_batch_id)
        .await?;
    let mut leaves = if let Some(checkpoint) = &checkpoint {
        ensure_leaf_index_in_range(checkpoint.inner.next_leaf_index, tree_depth)?;
        vec![U256::ZERO; checkpoint.inner.next_leaf_index as usize]
    } else {
        Vec::new()
    };

    {
        let mut leaf_values = tx
            .sync_log()
            .await?
            .stream_latest_leaf_values_at(max_batch_id);

        while let Some((leaf_index, maybe_commitment)) = leaf_values.try_next().await? {
            ensure_leaf_index_in_range(leaf_index + 1, tree_depth)?;
            if checkpoint.is_none() && leaf_index as usize >= leaves.len() {
                leaves.resize(leaf_index as usize + 1, U256::ZERO);
            }

            if (leaf_index as usize) < leaves.len() {
                leaves[leaf_index as usize] = maybe_commitment.unwrap_or(U256::ZERO);
            }
        }
    }

    let last_event_id = tx
        .world_id_registry_events()
        .await?
        .get_latest_id()
        .await?
        .unwrap_or_default();
    tx.commit().await?;

    Ok(SyncLogSnapshot {
        max_batch_id,
        checkpoint,
        leaves,
        last_event_id,
    })
}

async fn apply_batches(
    tree_state: &TreeState,
    batches: &[Persisted<Batch>],
    last_verified_batch_id: &mut u64,
) -> TreeResult<usize> {
    let processed = {
        let mut tree = tree_state.write().await;
        apply_batches_to_tree(&mut tree, tree_state.depth(), batches, last_verified_batch_id)?
    };

    tree_state.set_last_batch_id(*last_verified_batch_id).await;

    Ok(processed)
}

fn apply_batches_to_tree(
    tree: &mut MerkleTree,
    tree_depth: usize,
    batches: &[Persisted<Batch>],
    last_verified_batch_id: &mut u64,
) -> TreeResult<usize> {
    let mut processed_count = 0usize;

    for persisted in batches {
        apply_batch_to_tree(tree, tree_depth, persisted)?;
        processed_count += persisted.inner.changes.len();
        *last_verified_batch_id = persisted.batch_id;
    }

    Ok(processed_count)
}

fn apply_batch_to_tree(
    tree: &mut MerkleTree,
    tree_depth: usize,
    persisted: &Persisted<Batch>,
) -> TreeResult<()> {
    let header = &persisted.inner.header;
    ensure_leaf_index_in_range(header.next_leaf_index, tree_depth)?;

    for change in &persisted.inner.changes {
        ensure_leaf_index_in_range(change.leaf_index + 1, tree_depth)?;
        set_arbitrary_leaf(tree, change.leaf_index as usize, change.value());
    }

    if header.next_leaf_index > 0 && tree.num_leaves() < header.next_leaf_index as usize {
        set_arbitrary_leaf(tree, header.next_leaf_index as usize - 1, U256::ZERO);
    }

    verify_root(tree.root(), header.expected_root)
}

fn ensure_leaf_index_in_range(next_leaf_index: u64, tree_depth: usize) -> TreeResult<()> {
    let capacity = 1u64 << tree_depth;
    if next_leaf_index > capacity {
        return Err(TreeError::LeafIndexOutOfRange {
            leaf_index: next_leaf_index as usize,
            tree_depth,
        });
    }
    Ok(())
}

fn verify_root(actual: U256, expected: U256) -> TreeResult<()> {
    if actual != expected {
        return Err(TreeError::RootMismatch {
            actual: format!("0x{:x}", actual),
            expected: format!("0x{:x}", expected),
        });
    }
    Ok(())
}

/// Set a leaf value at the given index, extending the tree if necessary.
pub(crate) fn set_arbitrary_leaf(tree: &mut MerkleTree, leaf_index: usize, value: U256) {
    let num_leaves = tree.num_leaves();
    if leaf_index >= num_leaves {
        let num_zeros = leaf_index - num_leaves;
        let mut new = Vec::with_capacity(num_zeros + 1);
        new.resize(num_zeros, U256::ZERO);
        new.push(value);
        tree.extend_from_slice(&new);
    } else {
        tree.set_leaf(leaf_index, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 15: Cache file with no read permissions fails with CacheRestore.
    #[test]
    fn test_restore_unreadable_cache_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let cache_path =
                std::env::temp_dir().join(format!("test_perms_{}.mmap", uuid::Uuid::new_v4()));
            std::fs::write(&cache_path, b"some data").unwrap();
            std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o000)).unwrap();

            let result = restore_from_cache(&cache_path, 6);
            assert!(
                result.is_err(),
                "restore should fail on unreadable cache file"
            );

            // Restore permissions for cleanup
            std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::remove_file(&cache_path).unwrap();
        }
    }
}
