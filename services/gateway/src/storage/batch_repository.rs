use std::collections::HashSet;

use alloy::primitives::{B256, TxHash};
use redis::{Script, aio::ConnectionManager};

use crate::{
    error::GatewayResult,
    storage::types::{
        Batch, BatchId, BatchKind, BatchState, NewBatch, PreparedSubmission, RequestState,
        Timestamp,
    },
};

const READY_BATCHES_KEY: &str = "gateway:batches:ready";

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
        if batch.request_ids.is_empty() {
            return Err(redis::RedisError::from((
                redis::ErrorKind::Client,
                "cannot seal an empty batch",
            ))
            .into());
        }
        if batch
            .request_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != batch.request_ids.len()
        {
            return Err(redis::RedisError::from((
                redis::ErrorKind::Client,
                "cannot seal duplicate request ids",
            ))
            .into());
        }

        let record = Batch {
            id: batch.id,
            kind: batch.kind,
            request_ids: batch.request_ids,
            transaction: batch.transaction,
            state: BatchState::Ready,
            submission: None,
            created_at: batch.created_at,
            updated_at: batch.created_at,
        };
        let serialized_batch = serde_json::to_string(&record)?;
        let batched_state = serde_json::to_string(&RequestState::Batched(record.id))?;
        let mut manager = self.manager.clone();
        let script = Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) == 1 then
                return redis.error_reply('batch already exists')
            end

            for i = 4, #KEYS do
                local request = redis.call('GET', KEYS[i])
                local request_id = ARGV[i + 1]
                if not request or redis.call('ZSCORE', KEYS[3], request_id) == false then
                    return 0
                end

                local decoded = cjson.decode(request)
                if decoded.id ~= request_id or decoded.state ~= 'Queued' then
                    return 0
                end
            end

            for i = 4, #KEYS do
                local request_id = ARGV[i + 1]
                local decoded = cjson.decode(redis.call('GET', KEYS[i]))
                decoded.state = cjson.decode(ARGV[3])
                decoded.updated_at = tonumber(ARGV[4])
                redis.call('SET', KEYS[i], cjson.encode(decoded))
                redis.call('ZREM', KEYS[3], request_id)
            end

            redis.call('SET', KEYS[1], ARGV[1])
            redis.call('ZADD', KEYS[2], ARGV[4], ARGV[2])
            return 1
            "#,
        );
        let mut invocation = script.prepare_invoke();
        invocation
            .key(record.id.redis_key())
            .key(READY_BATCHES_KEY)
            .key(record.kind.queue_key());
        for request_id in &record.request_ids {
            invocation.key(request_id.redis_key());
        }
        invocation
            .arg(serialized_batch)
            .arg(record.id.0.to_string())
            .arg(batched_state)
            .arg(record.created_at);
        for request_id in &record.request_ids {
            invocation.arg(request_id.0.to_string());
        }

        let sealed: usize = invocation.invoke_async(&mut manager).await?;
        Ok(if sealed == 1 {
            SealBatchOutcome::Sealed(record.id)
        } else {
            SealBatchOutcome::RequestsNoLongerQueued
        })
    }

    /// Loads one batch from `gateway:batch:<batch-id>`.
    ///
    /// Returns `None` when the record does not exist. The ready queue and wallet
    /// assignment indexes are not consulted.
    pub(crate) async fn load(&self, batch_id: BatchId) -> GatewayResult<Option<Batch>> {
        let mut manager = self.manager.clone();
        let serialized: Option<String> = redis::cmd("GET")
            .arg(batch_id.redis_key())
            .query_async(&mut manager)
            .await?;
        serialized
            .map(|record| serde_json::from_str(&record).map_err(Into::into))
            .transpose()
    }

    /// Counts batches in `gateway:batches:ready`.
    ///
    /// When `kind` is set, batch records are inspected to count only that kind;
    /// otherwise this returns the sorted-set cardinality.
    pub(crate) async fn ready_len(&self, kind: Option<BatchKind>) -> GatewayResult<usize> {
        let mut manager = self.manager.clone();
        let Some(kind) = kind else {
            return Ok(redis::cmd("ZCARD")
                .arg(READY_BATCHES_KEY)
                .query_async(&mut manager)
                .await?);
        };

        const PAGE_SIZE: usize = 128;
        let mut offset = 0;
        let mut count = 0;
        loop {
            let members: Vec<String> = redis::cmd("ZRANGE")
                .arg(READY_BATCHES_KEY)
                .arg(offset)
                .arg(offset + PAGE_SIZE - 1)
                .query_async(&mut manager)
                .await?;
            if members.is_empty() {
                break;
            }
            offset += members.len();

            let keys: Vec<String> = members
                .iter()
                .map(|id| format!("gateway:batch:{id}"))
                .collect();
            let batches: Vec<Option<String>> = redis::cmd("MGET")
                .arg(keys)
                .query_async(&mut manager)
                .await?;
            for (member, serialized) in members.iter().zip(batches) {
                let Some(serialized) = serialized else {
                    continue;
                };
                let batch: Batch = serde_json::from_str(&serialized)?;
                if member == &batch.id.0.to_string()
                    && batch.kind == kind
                    && batch.state == BatchState::Ready
                {
                    count += 1;
                }
            }

            if members.len() < PAGE_SIZE {
                break;
            }
        }

        Ok(count)
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

#[cfg(test)]
mod tests {
    use alloy::primitives::{Bytes, U256, address};
    use redis::aio::ConnectionManager;
    use uuid::Uuid;
    use world_id_primitives::api_types::CreateAccountRequest;

    use super::{BatchRepository, READY_BATCHES_KEY, SealBatchOutcome};
    use crate::storage::{
        RequestRepository,
        test_support::start_redis,
        types::{
            BatchId, BatchKind, BatchState, NewBatch, NewRequest, RequestId, RequestPayload,
            RequestState, ResourceLock, TransactionIntent,
        },
    };

    async fn connect_repositories(redis_url: &str) -> (RequestRepository, BatchRepository) {
        let client = redis::Client::open(redis_url).unwrap();
        let manager = ConnectionManager::new(client).await.unwrap();
        (
            RequestRepository::new(manager.clone()),
            BatchRepository::new(manager),
        )
    }

    fn request(id: u128, account: u64, accepted_at: u64) -> NewRequest {
        NewRequest {
            id: RequestId(Uuid::from_u128(id)),
            payload: RequestPayload::Operation(Bytes::from_static(&[1, 2, 3])),
            accepted_at,
            resource_locks: vec![ResourceLock::Account(account)],
        }
    }

    fn batch(id: u128, request_ids: Vec<RequestId>) -> NewBatch {
        batch_of_kind(id, BatchKind::Operations, request_ids)
    }

    fn batch_of_kind(id: u128, kind: BatchKind, request_ids: Vec<RequestId>) -> NewBatch {
        NewBatch {
            id: BatchId(Uuid::from_u128(id)),
            kind,
            request_ids,
            transaction: TransactionIntent {
                to: address!("1111111111111111111111111111111111111111"),
                calldata: Bytes::from_static(&[4, 5, 6]),
                value: U256::from(7),
                gas_limit: 8,
            },
            created_at: 300,
        }
    }

    #[tokio::test]
    async fn seals_requests_into_immutable_ready_batch() {
        let (redis_url, _redis) = start_redis().await;
        let (requests, batches) = connect_repositories(&redis_url).await;
        let first = request(1, 10, 100);
        let first_id = first.id;
        let second = request(2, 20, 200);
        let second_id = second.id;
        requests.accept(first).await.unwrap();
        requests.accept(second).await.unwrap();
        let batch = batch(3, vec![first_id, second_id]);
        let batch_id = batch.id;

        assert_eq!(
            batches.seal(batch).await.unwrap(),
            SealBatchOutcome::Sealed(batch_id)
        );

        let stored = batches.load(batch_id).await.unwrap().unwrap();
        assert_eq!(stored.id, batch_id);
        assert_eq!(stored.kind, BatchKind::Operations);
        assert_eq!(stored.request_ids, vec![first_id, second_id]);
        assert_eq!(stored.state, BatchState::Ready);
        assert!(stored.submission.is_none());
        assert_eq!(stored.created_at, 300);
        assert_eq!(stored.updated_at, 300);
        assert_eq!(stored.transaction.calldata, Bytes::from_static(&[4, 5, 6]));

        for request_id in [first_id, second_id] {
            let request = requests.load(request_id).await.unwrap().unwrap();
            assert_eq!(request.state, RequestState::Batched(batch_id));
            assert_eq!(request.updated_at, 300);
        }
        assert_eq!(requests.queue_len(BatchKind::Operations).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn concurrent_sealing_assigns_each_request_to_one_batch() {
        let (redis_url, _redis) = start_redis().await;
        let (requests, batches) = connect_repositories(&redis_url).await;
        let request = request(1, 10, 100);
        let request_id = request.id;
        requests.accept(request).await.unwrap();
        let first_id = BatchId(Uuid::from_u128(2));
        let second_id = BatchId(Uuid::from_u128(3));

        let (first, second) = tokio::join!(
            batches.seal(batch(2, vec![request_id])),
            batches.seal(batch(3, vec![request_id]))
        );
        let first = first.unwrap();
        let second = second.unwrap();

        assert!(matches!(
            (&first, &second),
            (
                SealBatchOutcome::Sealed(_),
                SealBatchOutcome::RequestsNoLongerQueued
            ) | (
                SealBatchOutcome::RequestsNoLongerQueued,
                SealBatchOutcome::Sealed(_)
            )
        ));
        let request = requests.load(request_id).await.unwrap().unwrap();
        let RequestState::Batched(winner_id) = request.state else {
            panic!("request was not batched");
        };
        assert!(winner_id == first_id || winner_id == second_id);
        assert!(batches.load(winner_id).await.unwrap().is_some());
        let loser_id = if winner_id == first_id {
            second_id
        } else {
            first_id
        };
        assert!(batches.load(loser_id).await.unwrap().is_none());

        let mut manager = batches.manager.clone();
        let ready: usize = redis::cmd("ZCARD")
            .arg(READY_BATCHES_KEY)
            .query_async(&mut manager)
            .await
            .unwrap();
        assert_eq!(ready, 1);
    }

    #[tokio::test]
    async fn stale_member_aborts_sealing_without_partial_changes() {
        let (redis_url, _redis) = start_redis().await;
        let (requests, batches) = connect_repositories(&redis_url).await;
        let queued = request(1, 10, 100);
        let queued_id = queued.id;
        let failed = request(2, 20, 200);
        let failed_id = failed.id;
        requests.accept(queued).await.unwrap();
        requests.accept(failed).await.unwrap();
        requests
            .fail_queued(failed_id, "expired".to_string(), 250)
            .await
            .unwrap();
        let batch = batch(3, vec![queued_id, failed_id]);
        let batch_id = batch.id;

        assert_eq!(
            batches.seal(batch).await.unwrap(),
            SealBatchOutcome::RequestsNoLongerQueued
        );

        let queued = requests.load(queued_id).await.unwrap().unwrap();
        assert_eq!(queued.state, RequestState::Queued);
        assert_eq!(queued.updated_at, 100);
        assert!(batches.load(batch_id).await.unwrap().is_none());
        assert_eq!(requests.queue_len(BatchKind::Operations).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn counts_ready_batches_by_kind() {
        let (redis_url, _redis) = start_redis().await;
        let (requests, batches) = connect_repositories(&redis_url).await;
        let operation = request(1, 10, 100);
        let operation_id = operation.id;
        requests.accept(operation).await.unwrap();
        batches.seal(batch(2, vec![operation_id])).await.unwrap();
        let create_id = RequestId(Uuid::from_u128(3));
        requests
            .accept(NewRequest {
                id: create_id,
                payload: RequestPayload::CreateAccount(CreateAccountRequest {
                    recovery_address: None,
                    authenticator_addresses: vec![],
                    authenticator_pubkeys: vec![],
                    offchain_signer_commitment: U256::ZERO,
                }),
                accepted_at: 200,
                resource_locks: vec![],
            })
            .await
            .unwrap();
        batches
            .seal(batch_of_kind(4, BatchKind::CreateAccounts, vec![create_id]))
            .await
            .unwrap();

        assert_eq!(batches.ready_len(None).await.unwrap(), 2);
        assert_eq!(
            batches
                .ready_len(Some(BatchKind::Operations))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            batches
                .ready_len(Some(BatchKind::CreateAccounts))
                .await
                .unwrap(),
            1
        );

        let mut manager = batches.manager.clone();
        let _: usize = redis::cmd("DEL")
            .arg(BatchId(Uuid::from_u128(2)).redis_key())
            .query_async(&mut manager)
            .await
            .unwrap();
        assert_eq!(batches.ready_len(None).await.unwrap(), 2);
        assert_eq!(
            batches
                .ready_len(Some(BatchKind::Operations))
                .await
                .unwrap(),
            0
        );
    }
}
