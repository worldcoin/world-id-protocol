use alloy::primitives::{B256, TxHash};
use redis::aio::ConnectionManager;

use crate::{
    error::GatewayResult,
    storage::types::{Batch, BatchId, BatchKind, NewBatch, PreparedSubmission, Timestamp},
};

/// Result of attempting to atomically seal requests into an immutable batch.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SealBatchOutcome {
    /// The batch was persisted and published to the ready queue.
    Sealed(BatchId),
    /// At least one request was no longer queued; storage was not changed.
    RequestsNoLongerQueued,
}

/// Durable batch records, ready-queue indexing, and submission write-ahead log.
///
/// # Redis schema
///
/// - `gateway:batch:<batch-id>` stores one serialized [`Batch`], including its
///   immutable request IDs and intent, mutable state, and signed submission.
/// - `gateway:batches:ready` is a sorted set of ready batch IDs ordered by
///   `created_at` with a stable tie-breaker.
///
/// Atomic transitions also operate on request, wallet-assignment, and resource keys
/// owned by the other storage modules. The batch record is the source of truth;
/// the ready sorted set is an availability index.
#[derive(Clone)]
pub(crate) struct BatchRepository {
    manager: ConnectionManager,
}

impl BatchRepository {
    /// Creates a repository backed by the supplied Redis connection manager.
    ///
    /// This does not read or modify any Redis key.
    pub(crate) fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    /// Seals queued requests into an immutable batch and publishes it as ready.
    ///
    /// Atomically verifies the corresponding `gateway:request:<request-id>`
    /// records are queued, writes `gateway:batch:<batch-id>`, changes each
    /// request to `Batched(batch-id)`, removes the request IDs from their sorted
    /// queue, and adds the batch ID to `gateway:batches:ready`.
    pub(crate) async fn seal(&self, batch: NewBatch) -> GatewayResult<SealBatchOutcome> {
        unimplemented!()
    }

    /// Loads one batch from `gateway:batch:<batch-id>`.
    ///
    /// Returns `None` when the record does not exist. The ready queue and wallet
    /// assignment indexes are not consulted.
    pub(crate) async fn load(&self, batch_id: BatchId) -> GatewayResult<Option<Batch>> {
        unimplemented!()
    }

    /// Counts batches in `gateway:batches:ready`.
    ///
    /// When `kind` is set, batch records are inspected to count only that kind;
    /// otherwise this returns the sorted-set cardinality.
    pub(crate) async fn ready_len(&self, kind: Option<BatchKind>) -> GatewayResult<usize> {
        unimplemented!()
    }

    /// Persists the batch's signed transaction before broadcast.
    ///
    /// Atomically stores `submission` in `gateway:batch:<batch-id>` and moves the
    /// batch from assigned to pending. A batch accepts exactly one submission.
    /// The caller must confirm this write before sending the signed bytes to an
    /// RPC provider.
    pub(crate) async fn record_prepared_submission(
        &self,
        batch_id: BatchId,
        submission: PreparedSubmission,
    ) -> GatewayResult<()> {
        unimplemented!()
    }

    /// Marks the prepared submission as broadcast after the RPC call returns.
    ///
    /// Verifies `tx_hash` matches the submission in
    /// `gateway:batch:<batch-id>` and records `broadcast_at`. The signed bytes
    /// remain stored for reconciliation and idempotent rebroadcast.
    pub(crate) async fn mark_submission_broadcast(
        &self,
        batch_id: BatchId,
        tx_hash: TxHash,
        broadcast_at: Timestamp,
    ) -> GatewayResult<()> {
        unimplemented!()
    }

    /// Records receipt inclusion for the batch transaction.
    ///
    /// Updates `gateway:batch:<batch-id>` with the transaction hash, block hash,
    /// and block number. It does not release the wallet or finalize requests;
    /// those changes wait for canonical safe-block confirmation.
    pub(crate) async fn mark_included(
        &self,
        batch_id: BatchId,
        tx_hash: TxHash,
        block_hash: B256,
        block_number: u64,
        included_at: Timestamp,
    ) -> GatewayResult<()> {
        unimplemented!()
    }

    /// Atomically finalizes the batch and all of its requests at safe confirmation.
    ///
    /// Updates `gateway:batch:<batch-id>` and each
    /// `gateway:request:<request-id>`, deletes their
    /// `gateway:resource:<resource-id>` locks, and deletes the matching
    /// `gateway:wallet-assignment:<address>` key. Wallet eligibility remains in
    /// local gateway configuration.
    pub(crate) async fn finalize(
        &self,
        batch_id: BatchId,
        tx_hash: TxHash,
        finalized_at: Timestamp,
    ) -> GatewayResult<()> {
        unimplemented!()
    }

    /// Atomically fails a batch after safe revert or receipt-timeout expiry.
    ///
    /// A timeout is measured from [`PreparedSubmission::submitted_at`]. The
    /// caller must enforce the configured duration, verify no receipt exists,
    /// and verify the latest chain nonce has not advanced past the submitted
    /// nonce before invoking this transition.
    ///
    /// Updates `gateway:batch:<batch-id>` and each
    /// `gateway:request:<request-id>`, deletes their
    /// `gateway:resource:<resource-id>` locks, and deletes the matching
    /// `gateway:wallet-assignment:<address>` key. Wallet eligibility remains in
    /// local gateway configuration.
    pub(crate) async fn fail(
        &self,
        batch_id: BatchId,
        reason: String,
        resolved_at: Timestamp,
    ) -> GatewayResult<()> {
        unimplemented!()
    }
}
