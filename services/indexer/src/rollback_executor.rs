use alloy::{
    primitives::{Address, U256},
    providers::{DynProvider, Provider},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use world_id_registries::world_id::WorldIdRegistry;

use crate::{
    blockchain::RegistryEvent,
    db::{DB, DBResult, IsolationLevel, PostgresDBTransaction, WorldIdRegistryEventId},
    error::{IndexerError, IndexerResult},
    events_processor::EventsProcessor,
    tree::{TreeState, VersionedTreeState},
};

/// Walk backwards through all `RootRecorded` events in the DB and find the
/// most recent one that still exists on-chain (its log is still present at the
/// same block/log_index).
///
/// Returns the event ID rolled back to, or `None` if no `RootRecorded` events
/// exist or none are confirmed on-chain (in which case nothing is rolled back).
pub async fn rollback_to_last_valid_root(
    db: &DB,
    provider: &DynProvider,
    registry_address: Address,
    versioned_tree: &VersionedTreeState,
) -> IndexerResult<Option<WorldIdRegistryEventId>> {
    let Some(target_id) = find_last_valid_root(db, provider, registry_address).await? else {
        tracing::warn!("no valid root found on-chain, nothing to roll back to");
        return Ok(None);
    };

    let mut tx = db.transaction(IsolationLevel::Serializable).await?;
    let affected_leaf_indices = rollback_to_event(&mut tx, target_id).await?;
    tx.commit().await?;

    // Reconciliation reads the post-rollback account rows after the rollback
    // transaction commits. This relies on the current single-writer indexer
    // model and restart-after-reorg flow: no other indexer should advance the
    // DB between this commit and the tree update below. If either assumption
    // changes, keep the DB snapshot and tree reconciliation within one
    // serialized boundary.
    reconcile_tree_from_db(
        db,
        versioned_tree.tree_state(),
        &affected_leaf_indices,
        target_id,
    )
    .await?;

    Ok(Some(target_id))
}

/// Set each affected in-memory leaf to the post-rollback `accounts` row, or zero
/// when the account was removed.
pub async fn reconcile_tree_from_db(
    db: &DB,
    tree: &TreeState,
    affected_leaf_indices: &[u64],
    target_event_id: WorldIdRegistryEventId,
) -> IndexerResult<()> {
    for &leaf_index in affected_leaf_indices {
        let value = match db.accounts().get_account(leaf_index).await? {
            Some(account) => account.offchain_signer_commitment,
            None => U256::ZERO,
        };
        tree.set_leaf_at_index(leaf_index as usize, value).await?;
    }

    tree.set_last_synced_event_id(target_event_id).await;

    Ok(())
}

async fn find_last_valid_root(
    db: &DB,
    provider: &DynProvider,
    registry_address: Address,
) -> IndexerResult<Option<WorldIdRegistryEventId>> {
    const BATCH_SIZE: u64 = 100;
    let chain_head = provider
        .get_block_number()
        .await
        .map_err(|e| IndexerError::ContractCall(e.to_string()))?;

    // Sentinel: starts "after everything" so the first batch includes the latest events.
    // Use i64::MAX (not u64::MAX) because block numbers are stored as i64 in PostgreSQL;
    // casting u64::MAX to i64 would yield -1, which is less than any real block number.
    let mut cursor = WorldIdRegistryEventId {
        block_number: i64::MAX as u64,
        log_index: i64::MAX as u64,
    };

    loop {
        let batch = db
            .world_id_registry_events()
            .get_root_recorded_events_desc_before(cursor, BATCH_SIZE)
            .await?;

        if batch.is_empty() {
            return Ok(None);
        }

        for event in &batch {
            if event.block_number > chain_head {
                tracing::info!(
                    block_number = event.block_number,
                    chain_head,
                    log_index = event.log_index,
                    root = %format!("0x{:x}", event.details.root),
                    "RootRecorded log is above the current chain head, skipping"
                );
                continue;
            }

            let filter = Filter::new()
                .address(registry_address)
                .event_signature(WorldIdRegistry::RootRecorded::SIGNATURE_HASH)
                .from_block(event.block_number)
                .to_block(event.block_number);

            let logs = provider
                .get_logs(&filter)
                .await
                .map_err(|e| IndexerError::ContractCall(e.to_string()))?;

            let exists = logs.iter().any(|log| {
                if log.log_index != Some(event.log_index) {
                    return false;
                }
                match RegistryEvent::decode(log) {
                    Ok(decoded) => match &decoded.details {
                        RegistryEvent::RootRecorded(root_ev) => root_ev.root == event.details.root,
                        _ => false,
                    },
                    Err(_) => false,
                }
            });

            if exists {
                return Ok(Some(WorldIdRegistryEventId {
                    block_number: event.block_number,
                    log_index: event.log_index,
                }));
            }

            tracing::info!(
                block_number = event.block_number,
                log_index = event.log_index,
                root = %format!("0x{:x}", event.details.root),
                "RootRecorded log not found on-chain at expected position, skipping"
            );
        }

        let last = batch.last().expect("batch is non-empty");
        cursor = WorldIdRegistryEventId {
            block_number: last.block_number,
            log_index: last.log_index,
        };
    }
}

/// Roll back DB state to `event_id` (inclusive). Returns leaf indices whose
/// in-memory tree values may differ from the post-rollback DB.
pub async fn rollback_to_event(
    tx: &mut PostgresDBTransaction<'_>,
    event_id: WorldIdRegistryEventId,
) -> DBResult<Vec<u64>> {
    tracing::info!("rolling back up to event = {:?}", event_id);

    // Step 1: Get leaf indices where latest event is after rollback point
    let affected_leaf_indices = tx
        .accounts()
        .await?
        .get_after_event((event_id.block_number, event_id.log_index))
        .await?;

    tracing::info!("Found {} accounts to rollback", affected_leaf_indices.len());

    // Step 2: Remove those accounts
    let removed_accounts = tx
        .accounts()
        .await?
        .delete_after_event((event_id.block_number, event_id.log_index))
        .await?;

    tracing::info!("Removed {} accounts", removed_accounts);

    // Step 3: Remove world_id_registry_events greater than event_id
    let removed_registry_events = tx
        .world_id_registry_events()
        .await?
        .delete_after_event(&event_id)
        .await?;

    tracing::info!("Removed {} registry events", removed_registry_events);

    // Step 4: Replay events for each affected leaf index
    for leaf_index in &affected_leaf_indices {
        replay_events_for_leaf(tx, *leaf_index, &event_id).await?;
    }

    tracing::info!("Rollback completed successfully");

    Ok(affected_leaf_indices)
}

async fn replay_events_for_leaf(
    tx: &mut PostgresDBTransaction<'_>,
    leaf_index: u64,
    event_id: &WorldIdRegistryEventId,
) -> DBResult<()> {
    let events = tx
        .world_id_registry_events()
        .await?
        .get_events_for_leaf(leaf_index, event_id)
        .await?;

    tracing::info!(
        "Replaying {} events for leaf_index {}",
        events.len(),
        leaf_index
    );

    for (i, event) in events.iter().enumerate() {
        tracing::info!(
            "  Event {}: block={}, log={}, type={:?}",
            i,
            event.block_number,
            event.log_index,
            event.details
        );
    }

    for event in events {
        EventsProcessor::process_event(tx, &event).await?;
    }

    Ok(())
}
