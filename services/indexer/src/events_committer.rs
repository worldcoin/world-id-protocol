use std::time::Duration;

use crate::{
    batch::{Batch, BatchHeader, BatchKind, BatchOrigin, BatchRootCheck, LeafChange},
    blockchain::{BlockchainEvent, RegistryEvent, RootRecordedEvent},
    db::{DB, IsolationLevel, insert_sync_log_batch},
    error::{IndexerError, IndexerResult},
    events_processor::EventsProcessor,
    tree::{TreeState, apply_event_to_tree, extract_leaf_commitment},
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
/// 2. **Root integrity on every commit**: Before committing, the root that would
///    result from the batch is simulated and compared against the `RootRecorded`
///    event. A mismatch returns `ReorgDetected` without touching the tree or
///    committing the DB transaction. The tree is only updated after a successful
///    commit.
///
/// 3. **Reorg suffix is contiguous**: Because commits are rejected the moment a
///    bad root or conflicting hash is detected, any invalid state that does reach
///    the DB (from a post-commit reorg) forms a single contiguous suffix of
///    events — there is no interleaving of valid and invalid batches.
pub struct EventsCommitter<'a> {
    db: &'a DB,
    buffered_events: Vec<BlockchainEvent<RegistryEvent>>,
    tree: TreeState,
}

impl<'a> EventsCommitter<'a> {
    pub fn new(db: &'a DB, tree: TreeState) -> Self {
        Self {
            db,
            buffered_events: vec![],
            tree,
        }
    }

    /// Handle a single event: buffer it, and commit when a RootRecorded event
    /// is seen. Returns `true` when a DB commit happened (batch flushed).
    pub async fn handle_event(
        &mut self,
        event: BlockchainEvent<RegistryEvent>,
    ) -> IndexerResult<bool> {
        self.buffer_event(event);

        if let RegistryEvent::RootRecorded(_) =
            self.buffered_events.last().expect("just pushed").details
        {
            self.commit_events().await?;
            return Ok(true);
        }

        Ok(false)
    }

    fn buffer_event(&mut self, event: BlockchainEvent<RegistryEvent>) {
        tracing::info!(?event, "buffering event");
        self.buffered_events.push(event);
    }

    async fn commit_events(&mut self) -> IndexerResult<()> {
        const MAX_ATTEMPTS: u32 = 3;

        let root_recorded_block = self.buffered_events.last().map(|e| e.block_number);

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.attempt_commit().await {
                Ok(()) => return Ok(()),
                Err(e @ IndexerError::ReorgDetected { .. }) => return Err(e),
                Err(e) if attempt >= MAX_ATTEMPTS => {
                    tracing::error!(
                        ?e,
                        root_recorded_block,
                        attempt,
                        "DB commit failed after max attempts"
                    );
                    return Err(e);
                }
                Err(e) => {
                    let delay =
                        Duration::from_millis(500 * (1u64 << attempt)).min(Duration::from_secs(3));
                    tracing::warn!(
                        ?e,
                        root_recorded_block,
                        attempt,
                        ?delay,
                        "DB commit failed, retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn attempt_commit(&mut self) -> IndexerResult<()> {
        tracing::info!("committing events to DB");

        let batch_size = self.buffered_events.len();
        let started = std::time::Instant::now();

        let mut tx = self.db.transaction(IsolationLevel::Serializable).await?;
        let mut newly_committed_events = Vec::new();
        let mut checkpoint_batch_id = None;

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
            newly_committed_events.push(event);
        }

        let batch_block_numbers: Vec<i64> = self
            .buffered_events
            .iter()
            .map(|e| e.block_number as i64)
            .collect();

        let blocks = tx
            .world_id_registry_events()
            .await?
            .get_blocks_with_conflicting_hashes(&batch_block_numbers)
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

        if let Some(BlockchainEvent {
            block_number,
            log_index,
            details:
                RegistryEvent::RootRecorded(RootRecordedEvent {
                    root: expected_root,
                    timestamp,
                }),
            ..
        }) = self.buffered_events.last()
        {
            let block_number = *block_number;
            let expected_root = *expected_root;

            let events_for_batch: Vec<&BlockchainEvent<RegistryEvent>> = if !newly_committed_events.is_empty() {
                newly_committed_events.clone()
            } else {
                self.buffered_events.iter().collect()
            };

            let batch = build_forward_batch(
                &events_for_batch,
                expected_root,
                *log_index,
                block_number,
                *timestamp,
                tx.accounts().await?.get_next_leaf_index().await?,
            );

            match self.tree.simulate_batch(&batch).await? {
                BatchRootCheck::Match => {
                    if !newly_committed_events.is_empty() {
                        checkpoint_batch_id =
                            Some(insert_sync_log_batch(&mut tx, &batch).await?);
                    }
                }
                BatchRootCheck::Mismatch { simulated } => {
                    return Err(IndexerError::ReorgDetected {
                        block_number,
                        reason: format!(
                            "simulated tree root (0x{:x}) does not match RootRecorded root (0x{:x})",
                            simulated, expected_root,
                        ),
                    });
                }
            }
        }

        tx.commit().await?;

        if let Some(_checkpoint_batch_id) = checkpoint_batch_id {
            crate::tree::cached_tree::sync_from_db(self.db, &self.tree).await?;
        } else {
            let tree = &self.tree;
            for event in self.buffered_events.iter() {
                apply_event_to_tree(tree, event).await?;
            }
        }

        let latency_ms = started.elapsed().as_millis() as f64;
        crate::metrics::record_commit(batch_size, latency_ms);

        self.buffered_events.clear();

        Ok(())
    }
}

fn build_forward_batch(
    events: &[&BlockchainEvent<RegistryEvent>],
    expected_root: alloy::primitives::U256,
    log_index: u64,
    block_number: u64,
    onchain_timestamp: alloy::primitives::U256,
    next_leaf_index: u64,
) -> Batch {
    let changes = events
        .iter()
        .filter_map(|event| {
            extract_leaf_commitment(&event.details)
                .map(|(leaf_index, commitment)| LeafChange::new(leaf_index, commitment))
        })
        .collect();

    Batch {
        header: BatchHeader {
            kind: BatchKind::Forward,
            expected_root,
            next_leaf_index,
            origin: BatchOrigin {
                block_number,
                log_index,
                onchain_timestamp: onchain_timestamp.as_limbs()[0],
            },
        },
        changes,
    }
}
