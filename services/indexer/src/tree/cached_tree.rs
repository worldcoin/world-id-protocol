use std::path::Path;

use alloy::primitives::U256;
use futures_util::TryStreamExt as _;
use tracing::{info, instrument, warn};

use super::{
    TreeError, TreeResult, TreeState,
    cache::{
        self, CacheStatus, metadata_path, persist_clean_checkpoint, persist_dirty_checkpoint,
        remove_cache_files,
    },
};
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
/// Attempts to restore a verified mmap cache when a sidecar metadata file is
/// present. Clean caches are validated against the exact sync batch checkpoint;
/// dirty caches re-apply the in-flight checkpoint range before continuing.
/// Any validation or storage failure falls back to a full rebuild from
/// `sync_batch` / `sync_leaf_change`.
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
    let meta_path = metadata_path(cache_path);

    let init_result = if cache_path.exists() && meta_path.exists() {
        match try_restore_from_cache(db, cache_path, &meta_path, tree_depth).await {
            Ok(result) => Ok(result),
            Err(error) if is_rebuildable_validation_error(&error) => {
                warn!(?error, "cache restore failed, rebuilding from sync batches");
                remove_cache_files(cache_path);
                build_from_sync_log_with_cache(db, cache_path, tree_depth).await
            }
            Err(error) => Err(error.into()),
        }
    } else {
        build_from_sync_log_with_cache(db, cache_path, tree_depth).await
    }?;

    let (tree, last_event_id, last_batch_id) = init_result;
    let tree_state = TreeState::new_with_batch_id(
        tree,
        tree_depth,
        last_event_id,
        last_batch_id,
        Some(cache_path.to_path_buf()),
    );
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

/// Mark the cache dirty before applying a checkpoint, then replay the sync
/// batches through `sync_from_db()` and persist clean metadata on success.
pub async fn apply_checkpoint_from_sync_log(
    db: &DB,
    tree_state: &TreeState,
    base_batch_id: u64,
    target_batch_id: u64,
) -> TreeResult<()> {
    persist_dirty_checkpoint(
        tree_state.cache_path(),
        tree_state.depth(),
        base_batch_id,
        target_batch_id,
    )?;

    sync_from_db(db, tree_state).await?;
    Ok(())
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

struct RestoreResult {
    tree: MerkleTree,
    last_event_id: WorldIdRegistryEventId,
    last_batch_id: u64,
}

async fn try_restore_from_cache(
    db: &DB,
    cache_path: &Path,
    meta_path: &Path,
    tree_depth: usize,
) -> TreeResult<(MerkleTree, WorldIdRegistryEventId, u64)> {
    let metadata = cache::read_metadata(meta_path)?;
    metadata.ensure_tree_depth(tree_depth)?;

    let tree = unsafe { cache::restore_tree(cache_path, tree_depth)? };

    let last_event_id = db
        .world_id_registry_events()
        .get_latest_id()
        .await?
        .unwrap_or_default();

    let restored = match metadata.status {
        CacheStatus::Clean {
            last_verified_batch_id,
        } => {
            validate_clean_cache(db, &tree, last_verified_batch_id).await?;
            RestoreResult {
                tree,
                last_event_id,
                last_batch_id: last_verified_batch_id,
            }
        }
        CacheStatus::Dirty {
            base_batch_id,
            target_batch_id,
        } => {
            recover_dirty_cache(
                db,
                cache_path,
                tree,
                tree_depth,
                base_batch_id,
                target_batch_id,
                last_event_id,
            )
            .await?
        }
    };

    Ok((
        restored.tree,
        restored.last_event_id,
        restored.last_batch_id,
    ))
}

async fn validate_clean_cache(
    db: &DB,
    tree: &MerkleTree,
    last_verified_batch_id: u64,
) -> TreeResult<()> {
    if last_verified_batch_id == 0 {
        let max_batch_id = db.sync_log().get_max_batch_id().await?;
        if max_batch_id == 0 {
            return Ok(());
        }
        return Err(TreeError::CacheValidation(
            "clean metadata points to batch_id 0 but sync batches are non-empty".to_string(),
        ));
    }

    let checkpoint = db
        .sync_log()
        .get_batch_at(last_verified_batch_id)
        .await?
        .ok_or_else(|| {
            TreeError::CacheValidation(format!(
                "missing sync batch at batch_id {last_verified_batch_id}"
            ))
        })?;

    verify_root(tree.root(), checkpoint.inner.expected_root)
}

async fn recover_dirty_cache(
    db: &DB,
    cache_path: &Path,
    mut tree: MerkleTree,
    tree_depth: usize,
    base_batch_id: u64,
    target_batch_id: u64,
    last_event_id: WorldIdRegistryEventId,
) -> TreeResult<RestoreResult> {
    let checkpoint = db
        .sync_log()
        .get_batch_at(target_batch_id)
        .await?
        .ok_or_else(|| {
            TreeError::CacheValidation(format!(
                "missing sync batch at dirty target batch_id {target_batch_id}"
            ))
        })?;

    let batches = db
        .sync_log()
        .get_batches(base_batch_id, Some(target_batch_id), None)
        .await?;

    let mut last_verified_batch_id = base_batch_id;
    apply_batches_to_tree(
        &mut tree,
        tree_depth,
        &batches,
        &mut last_verified_batch_id,
        Some(cache_path),
    )?;

    if last_verified_batch_id != target_batch_id {
        return Err(TreeError::CacheValidation(format!(
            "dirty recovery did not reach target batch_id {target_batch_id}"
        )));
    }

    verify_root(tree.root(), checkpoint.inner.expected_root)?;

    persist_clean_checkpoint(Some(cache_path), tree_depth, target_batch_id)?;

    Ok(RestoreResult {
        tree,
        last_event_id,
        last_batch_id: target_batch_id,
    })
}

/// Build tree from the sync batch projection with mmap backing.
#[instrument(level = "info", skip_all)]
async fn build_from_sync_log_with_cache(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<(MerkleTree, WorldIdRegistryEventId, u64)> {
    info!("Building tree from sync batches with mmap cache");

    remove_cache_files(cache_path);

    let snapshot = load_sync_log_snapshot(db, tree_depth).await?;

    info!(
        len = snapshot.leaves.len(),
        max_batch_id = snapshot.max_batch_id,
        "Building Tree"
    );

    let tree = unsafe { cache::create_tree(cache_path, tree_depth, &snapshot.leaves)? };

    if let Some(checkpoint) = &snapshot.checkpoint {
        verify_root(tree.root(), checkpoint.inner.expected_root)?;
        persist_clean_checkpoint(Some(cache_path), tree_depth, checkpoint.batch_id)?;
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
        apply_batches_to_tree(
            &mut tree,
            tree_state.depth(),
            batches,
            last_verified_batch_id,
            tree_state.cache_path(),
        )?
    };

    tree_state.set_last_batch_id(*last_verified_batch_id).await;

    Ok(processed)
}

fn apply_batches_to_tree(
    tree: &mut MerkleTree,
    tree_depth: usize,
    batches: &[Persisted<Batch>],
    last_verified_batch_id: &mut u64,
    cache_path: Option<&Path>,
) -> TreeResult<usize> {
    let mut processed_count = 0usize;

    for persisted in batches {
        apply_batch_to_tree(tree, tree_depth, persisted)?;
        processed_count += persisted.inner.changes.len();
        *last_verified_batch_id = persisted.batch_id;
        persist_clean_checkpoint(cache_path, tree_depth, persisted.batch_id)?;
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

fn is_rebuildable_validation_error(error: &TreeError) -> bool {
    matches!(
        error,
        TreeError::RootMismatch { .. }
            | TreeError::StaleCache { .. }
            | TreeError::InvalidSyncLogRow(_)
            | TreeError::CacheRestore(_)
            | TreeError::InvalidCacheMetadata(_)
            | TreeError::TreeDepthMismatch { .. }
            | TreeError::CacheValidation(_)
            | TreeError::CacheCreate(_)
    )
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
