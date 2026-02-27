use alloy::providers::DynProvider;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{
    blockchain::{BlockchainEvent, RegistryEvent, RootRecordedEvent},
    db::{DB, IsolationLevel},
    error::{IndexerError, IndexerResult},
    events_processor::EventsProcessor,
    tree::{VersionedTreeState, apply_event_to_tree},
};

/// Buffers blockchain events and commits them to the database in batches,
/// one batch per `RootRecorded` event.
///
/// # DB invariants enforced
///
/// 1. **No hash conflicts**: If an event already exists in the DB with a different
///    `block_hash` or `tx_hash` for the same `(block_number, log_index)`, the
///    transaction is aborted and `ReorgDetected` is returned. A final post-write
///    check catches any cross-event conflicts within the same batch.
///
/// 2. **No invalid roots at write time**: When a `registry` is configured, the
///    root from each `RootRecorded` event is validated on-chain via `isValidRoot`
///    *before* the DB transaction begins. A root that fails this check returns
///    `ReorgDetected` without touching the DB.
///
/// 3. **Reorg suffix is contiguous**: Because commits are rejected the moment a
///    bad root or conflicting hash is detected, any invalid state that does reach
///    the DB (from a post-commit reorg) forms a single contiguous suffix of
///    events — there is no interleaving of valid and invalid batches.
pub struct EventsCommitter<'a> {
    db: &'a DB,
    buffered_events: Vec<BlockchainEvent<RegistryEvent>>,
    versioned_tree: Option<VersionedTreeState>,
    registry: Option<WorldIdRegistryInstance<DynProvider>>,
}

impl<'a> EventsCommitter<'a> {
    pub fn new(db: &'a DB) -> Self {
        Self {
            db,
            buffered_events: vec![],
            versioned_tree: None,
            registry: None,
        }
    }

    pub fn with_versioned_tree(
        mut self,
        tree: VersionedTreeState,
        registry: WorldIdRegistryInstance<DynProvider>,
    ) -> Self {
        self.versioned_tree = Some(tree);
        self.registry = Some(registry);
        self
    }

    /// Handle a single event: buffer it, and commit when a RootRecorded event
    /// is seen. Returns `true` when a DB commit happened (batch flushed).
    pub async fn handle_event(
        &mut self,
        event: BlockchainEvent<RegistryEvent>,
    ) -> IndexerResult<bool> {
        if let Some(tree) = &self.versioned_tree {
            apply_event_to_tree(tree, &event).await?;
        }

        self.buffer_event(event);

        if let RegistryEvent::RootRecorded(ref root_recorded) =
            self.buffered_events.last().expect("just pushed").details
        {
            let root_recorded = root_recorded.clone();
            let block_number = self
                .buffered_events
                .last()
                .expect("just pushed")
                .block_number;
            self.commit_events(&root_recorded, block_number).await?;
            if let Some(tree) = &self.versioned_tree {
                tree.prune(block_number).await;
            }
            return Ok(true);
        }

        Ok(false)
    }

    fn buffer_event(&mut self, event: BlockchainEvent<RegistryEvent>) {
        tracing::info!(?event, "buffering event");
        self.buffered_events.push(event);
    }

    async fn commit_events(
        &mut self,
        root_recorded: &RootRecordedEvent,
        block_number: u64,
    ) -> IndexerResult<()> {
        tracing::info!("committing events to DB");

        // Check root validity on-chain before touching the DB.
        if let Some(registry) = &self.registry {
            let root = root_recorded.root;
            let valid = registry
                .isValidRoot(root)
                .call()
                .await
                .map_err(|e| IndexerError::ContractCall(e.to_string()))?;

            if !valid {
                return Err(IndexerError::ReorgDetected {
                    block_number,
                    reason: format!(
                        "root 0x{:x} from block {} is not valid on-chain",
                        root, block_number
                    ),
                });
            }

            tracing::info!(
                root = %format!("0x{:x}", root),
                block_number,
                "root validated on-chain"
            );
        }

        self.commit_to_db().await?;

        Ok(())
    }

    async fn commit_to_db(&mut self) -> IndexerResult<()> {
        let mut tx = self.db.transaction(IsolationLevel::Serializable).await?;

        for event in self.buffered_events.iter() {
            let db_event = tx
                .world_id_registry_events()
                .await?
                .get_event((event.block_number, event.log_index))
                .await?;

            if let Some(db_event) = db_event {
                if db_event.block_hash != event.block_hash {
                    return Err(IndexerError::ReorgDetected {
                        block_number: event.block_number,
                        reason: format!(
                            "Event at block {} log_index {} exists with different block_hash (db: {}, event: {})",
                            event.block_number,
                            event.log_index,
                            db_event.block_hash,
                            event.block_hash,
                        ),
                    });
                }

                if db_event.tx_hash != event.tx_hash {
                    return Err(IndexerError::ReorgDetected {
                        block_number: event.block_number,
                        reason: format!(
                            "Event at block {} log_index {} exists with different tx_hash (db: {}, event: {})",
                            event.block_number, event.log_index, db_event.tx_hash, event.tx_hash,
                        ),
                    });
                }

                tracing::info!(
                    block_number = event.block_number,
                    log_index = event.log_index,
                    "Event already processed, skipping"
                );
                continue;
            } else {
                tx.world_id_registry_events()
                    .await?
                    .insert_event(event)
                    .await?;
            }

            EventsProcessor::process_event(&mut tx, event).await?;
        }

        let blocks = tx
            .world_id_registry_events()
            .await?
            .get_blocks_with_conflicting_hashes()
            .await?;

        if !blocks.is_empty() {
            return Err(IndexerError::ReorgDetected {
                block_number: blocks[0].block_number,
                reason: format!(
                    "After processing events detected blocks with mismatch on block hashes: {:?}",
                    blocks,
                ),
            });
        }

        tx.commit().await?;

        self.buffered_events.clear();

        Ok(())
    }
}
