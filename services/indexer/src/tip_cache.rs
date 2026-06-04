//! In-memory tip cache for the indexer.
//!
//! The indexer polls registry events at the chain **tip** (no confirmation lag)
//! and applies them immediately to the in-memory Merkle tree, so inclusion
//! proofs reflect the latest state. Those updates are held in a **pending
//! buffer** and are only persisted to the database once their block is at least
//! `confirmations` deep — that is the durable, "confirmed" store.
//!
//! Because nothing unconfirmed is written to the database, a reorg inside the
//! unconfirmed window is cheap to recover from: the in-memory tree is rolled
//! back to the common ancestor (via [`VersionedTreeState::rollback_to`]) and the
//! canonical events are replayed. The database is never touched.
//!
//! Reorg *detection* is driven by the poll loop (which has RPC access) using the
//! per-block canonical hashes tracked here; see [`TipCache::block_hashes_desc`].

use std::collections::VecDeque;

use alloy::primitives::U256;

use crate::{
    blockchain::{BlockchainEvent, RegistryEvent},
    db::{DB, IsolationLevel, WorldIdRegistryEventId},
    error::{IndexerError, IndexerResult},
    events_processor::EventsProcessor,
    tree::{VersionedTreeState, apply_event_to_tree},
};

/// Holds the tip view of the tree plus the buffer of applied-but-unconfirmed
/// events awaiting database commit.
pub struct TipCache {
    /// The in-memory tree, kept at the tip. Shared with the HTTP server, so
    /// proofs served reflect unconfirmed updates held here.
    tree: VersionedTreeState,
    /// Applied-but-uncommitted events, ordered ascending by `(block, log_index)`.
    pending: VecDeque<BlockchainEvent<RegistryEvent>>,
    /// Canonical block hash of each event-bearing pending block, ascending by
    /// block number (one entry per block). Used for reorg detection.
    block_hashes: VecDeque<(u64, U256)>,
    /// Number of confirmations a block must reach before its events are
    /// committed to the database.
    confirmations: u64,
    /// `(block, log_index)` of the most recent event committed to the database.
    committed: WorldIdRegistryEventId,
}

impl TipCache {
    pub fn new(
        tree: VersionedTreeState,
        confirmations: u64,
        committed: WorldIdRegistryEventId,
    ) -> Self {
        Self {
            tree,
            pending: VecDeque::new(),
            block_hashes: VecDeque::new(),
            confirmations,
            committed,
        }
    }

    /// The in-memory tree (tip view).
    pub fn tree(&self) -> &VersionedTreeState {
        &self.tree
    }

    /// Highest block currently held in the pending buffer, if any.
    pub fn highest_pending_block(&self) -> Option<u64> {
        self.block_hashes.back().map(|(b, _)| *b)
    }

    /// `(block, canonical_hash)` for every event-bearing pending block, newest
    /// first. The poll loop walks this to locate the common ancestor on a reorg.
    pub fn block_hashes_desc(&self) -> Vec<(u64, U256)> {
        self.block_hashes.iter().rev().copied().collect()
    }

    /// Apply a single canonical event to the tip tree and record it as pending.
    ///
    /// On a `RootRecorded` event the resulting tree root is checked against the
    /// on-chain root; a mismatch indicates a missed/extra event (or a reorg
    /// observed mid-fetch) and is surfaced as [`IndexerError::ReorgDetected`].
    pub async fn apply(&mut self, event: BlockchainEvent<RegistryEvent>) -> IndexerResult<()> {
        apply_event_to_tree(&self.tree, &event).await?;

        // Track one canonical hash per block for reorg detection.
        match self.block_hashes.back() {
            Some((b, _)) if *b == event.block_number => {}
            _ => self
                .block_hashes
                .push_back((event.block_number, event.block_hash)),
        }

        let block_number = event.block_number;
        let expected_root = match &event.details {
            RegistryEvent::RootRecorded(rr) => Some(rr.root),
            _ => None,
        };

        self.pending.push_back(event);
        crate::metrics::set_chain_processed_block(block_number);

        if let Some(expected) = expected_root {
            let actual = self.tree.root().await;
            if actual != expected {
                return Err(IndexerError::ReorgDetected {
                    block_number,
                    reason: format!(
                        "tip tree root (0x{actual:x}) does not match RootRecorded root (0x{expected:x})"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Roll the tip tree and pending buffer back so that no event from a block
    /// after `block` remains applied. Used to discard a reorged suffix.
    pub async fn rollback_after_block(&mut self, block: u64) -> IndexerResult<()> {
        // `log_index: u64::MAX` keeps every event in `block` and discards
        // everything in later blocks.
        let target = WorldIdRegistryEventId {
            block_number: block,
            log_index: u64::MAX,
        };
        self.tree.rollback_to(target).await?;

        while self.pending.back().is_some_and(|e| e.block_number > block) {
            self.pending.pop_back();
        }
        while self.block_hashes.back().is_some_and(|(b, _)| *b > block) {
            self.block_hashes.pop_back();
        }

        Ok(())
    }

    /// Commit the contiguous prefix of pending events whose block is at or below
    /// `head - confirmations` to the database, then drop them from the buffer.
    ///
    /// The tree is **not** touched here — those updates were already applied at
    /// the tip; this only makes them durable.
    pub async fn flush_confirmed(&mut self, db: &DB, head: u64) -> IndexerResult<()> {
        let confirmed_through = head.saturating_sub(self.confirmations);

        if self
            .pending
            .front()
            .is_none_or(|e| e.block_number > confirmed_through)
        {
            return Ok(());
        }

        let mut tx = db.transaction(IsolationLevel::Serializable).await?;
        let mut last = self.committed;
        let mut flushed = 0usize;

        while let Some(front) = self.pending.front() {
            if front.block_number > confirmed_through {
                break;
            }
            let event = self.pending.pop_front().expect("front exists");
            tx.world_id_registry_events()
                .await?
                .insert_event(&event)
                .await?;
            EventsProcessor::process_event(&mut tx, &event).await?;
            last = WorldIdRegistryEventId {
                block_number: event.block_number,
                log_index: event.log_index,
            };
            flushed += 1;
        }

        tx.commit().await?;

        self.committed = last;
        while self
            .block_hashes
            .front()
            .is_some_and(|(b, _)| *b <= confirmed_through)
        {
            self.block_hashes.pop_front();
        }
        self.tree.set_last_synced_event_id(last).await;

        tracing::debug!(
            flushed,
            confirmed_through,
            committed = ?self.committed,
            "flushed confirmed events to DB"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::TreeState;

    fn tmp_file() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("tip_cache_test_{}.tmp", uuid::Uuid::new_v4()));
        p
    }

    fn cache(confirmations: u64) -> TipCache {
        let tree = unsafe { TreeState::new_empty(6, tmp_file()).unwrap() };
        let versioned = VersionedTreeState::new(tree, 10_000);
        TipCache::new(versioned, confirmations, WorldIdRegistryEventId::default())
    }

    fn account_created(
        block: u64,
        log_index: u64,
        leaf: u64,
        commitment: u64,
    ) -> BlockchainEvent<RegistryEvent> {
        BlockchainEvent {
            block_number: block,
            block_hash: U256::from(block), // distinct per block by default
            tx_hash: U256::from(1),
            log_index,
            details: RegistryEvent::AccountCreated(
                world_id_registries::world_id::WorldIdRegistry::AccountCreated {
                    leafIndex: leaf,
                    recoveryAddress: alloy::primitives::Address::ZERO,
                    authenticatorAddresses: vec![],
                    authenticatorPubkeys: vec![],
                    offchainSignerCommitment: U256::from(commitment),
                },
            ),
        }
    }

    #[tokio::test]
    async fn apply_updates_tree_and_tracks_block_hash() {
        let mut c = cache(2);
        let root0 = c.tree().root().await;

        c.apply(account_created(10, 0, 1, 42)).await.unwrap();

        assert_ne!(
            c.tree().root().await,
            root0,
            "tip tree should reflect update"
        );
        assert_eq!(c.highest_pending_block(), Some(10));
    }

    #[tokio::test]
    async fn one_block_hash_entry_per_block() {
        let mut c = cache(2);
        c.apply(account_created(10, 0, 1, 42)).await.unwrap();
        c.apply(account_created(10, 1, 2, 43)).await.unwrap();
        c.apply(account_created(11, 0, 3, 44)).await.unwrap();

        let hashes = c.block_hashes_desc();
        assert_eq!(
            hashes.iter().map(|(b, _)| *b).collect::<Vec<_>>(),
            vec![11, 10]
        );
    }

    #[tokio::test]
    async fn rollback_after_block_restores_tip() {
        let mut c = cache(2);
        c.apply(account_created(10, 0, 1, 42)).await.unwrap();
        let root_at_10 = c.tree().root().await;
        c.apply(account_created(11, 0, 2, 43)).await.unwrap();
        assert_ne!(c.tree().root().await, root_at_10);

        c.rollback_after_block(10).await.unwrap();

        assert_eq!(
            c.tree().root().await,
            root_at_10,
            "tree rolled back to block 10"
        );
        assert_eq!(c.highest_pending_block(), Some(10));
    }

    #[tokio::test]
    async fn rollback_clears_all_when_before_first() {
        let mut c = cache(2);
        let root_empty = c.tree().root().await;
        c.apply(account_created(10, 0, 1, 42)).await.unwrap();

        c.rollback_after_block(9).await.unwrap();

        assert_eq!(c.tree().root().await, root_empty);
        assert_eq!(c.highest_pending_block(), None);
    }
}
