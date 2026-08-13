use redis::{Script, aio::ConnectionManager};

use crate::{
    error::GatewayResult,
    storage::types::{
        BatchKind, NewRequest, RequestId, RequestState, ResourceLock, StoredRequest, Timestamp,
    },
};

/// Result of atomically persisting a request and acquiring its resource locks.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum AcceptRequestOutcome {
    /// The request record, queue entry, and every resource lock were created.
    Accepted,
    /// The named resource was already locked; storage was not changed.
    ResourceLocked(ResourceLock),
}

/// Durable request records, admission locks, and ordered batching queues.
///
/// # Redis schema
///
/// - `gateway:request:<request-id>` stores one serialized [`StoredRequest`].
/// - `gateway:requests:create` is a sorted set of queued create request IDs.
/// - `gateway:requests:ops` is a sorted set of queued operation request IDs.
/// - `gateway:resource:<resource-id>` maps a locked resource to its request ID.
///
/// Queue scores use `accepted_at`; request IDs provide deterministic ordering
/// when scores match. Request records remain the source of
/// truth; sorted sets are indexes. Acceptance and terminal transitions update
/// records, queue indexes, and resource locks atomically.
#[derive(Clone)]
pub(crate) struct RequestRepository {
    manager: ConnectionManager,
}

impl RequestRepository {
    /// Creates a repository backed by the supplied Redis connection manager.
    ///
    /// This does not read or modify any Redis key.
    pub(crate) fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    /// Persists a queued request and acquires all of its resource locks.
    ///
    /// Atomically creates `gateway:request:<request-id>`, adds the ID to
    /// `gateway:requests:create` or `gateway:requests:ops`, and creates each
    /// `gateway:resource:<resource-id>` lock. If any lock exists, returns
    /// [`AcceptRequestOutcome::ResourceLocked`] without changing storage.
    pub(crate) async fn accept(&self, request: NewRequest) -> GatewayResult<AcceptRequestOutcome> {
        let kind = request.payload.batch_kind();
        let record = StoredRequest {
            id: request.id,
            payload: request.payload,
            state: RequestState::Queued,
            accepted_at: request.accepted_at,
            updated_at: request.accepted_at,
            resource_locks: request.resource_locks,
        };
        let serialized = serde_json::to_string(&record)?;
        let mut manager = self.manager.clone();
        let script = Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) == 1 then
                return redis.error_reply('request already exists')
            end

            for i = 3, #KEYS do
                if redis.call('EXISTS', KEYS[i]) == 1 then
                    return i
                end
            end

            redis.call('SET', KEYS[1], ARGV[1])
            redis.call('ZADD', KEYS[2], ARGV[3], ARGV[2])
            for i = 3, #KEYS do
                redis.call('SET', KEYS[i], ARGV[2])
            end
            return 0
            "#,
        );
        let mut invocation = script.prepare_invoke();
        invocation.key(record.id.redis_key()).key(kind.queue_key());
        for resource in &record.resource_locks {
            invocation.key(resource.redis_key());
        }
        invocation
            .arg(serialized)
            .arg(record.id.0.to_string())
            .arg(record.accepted_at);

        let locked_key_index: usize = invocation.invoke_async(&mut manager).await?;
        if locked_key_index == 0 {
            Ok(AcceptRequestOutcome::Accepted)
        } else {
            Ok(AcceptRequestOutcome::ResourceLocked(
                record.resource_locks[locked_key_index - 3],
            ))
        }
    }

    /// Loads one request from `gateway:request:<request-id>`.
    ///
    /// Returns `None` when the record does not exist. Queue indexes and resource
    /// locks are not consulted.
    pub(crate) async fn load(&self, request_id: RequestId) -> GatewayResult<Option<StoredRequest>> {
        let mut manager = self.manager.clone();
        let serialized: Option<String> = redis::cmd("GET")
            .arg(request_id.redis_key())
            .query_async(&mut manager)
            .await?;
        serialized
            .map(|record| serde_json::from_str(&record).map_err(Into::into))
            .transpose()
    }

    /// Loads request records from `gateway:request:<request-id>` in one round trip.
    ///
    /// Results preserve input order, including `None` for every missing record.
    pub(crate) async fn load_many(
        &self,
        request_ids: &[RequestId],
    ) -> GatewayResult<Vec<Option<StoredRequest>>> {
        if request_ids.is_empty() {
            return Ok(Vec::new());
        }

        let keys: Vec<String> = request_ids.iter().map(|id| id.redis_key()).collect();
        let mut manager = self.manager.clone();
        let records: Vec<Option<String>> = redis::cmd("MGET")
            .arg(keys)
            .query_async(&mut manager)
            .await?;
        records
            .into_iter()
            .map(|record| {
                record
                    .map(|value| serde_json::from_str(&value).map_err(Into::into))
                    .transpose()
            })
            .collect()
    }

    /// Returns up to `limit` oldest queued requests of `kind`.
    ///
    /// Reads IDs from `gateway:requests:create` or `gateway:requests:ops`, then
    /// loads their `gateway:request:<request-id>` records. This is an inspection
    /// operation: it does not reserve or remove requests from the queue.
    pub(crate) async fn oldest_queued(
        &self,
        kind: BatchKind,
        limit: usize,
    ) -> GatewayResult<Vec<StoredRequest>> {
        unimplemented!()
    }

    /// Counts members in the sorted queue for `kind`.
    ///
    /// Operates on `gateway:requests:create` or `gateway:requests:ops` without
    /// loading request records.
    pub(crate) async fn queue_len(&self, kind: BatchKind) -> GatewayResult<usize> {
        let mut manager = self.manager.clone();
        Ok(redis::cmd("ZCARD")
            .arg(kind.queue_key())
            .query_async(&mut manager)
            .await?)
    }

    /// Fails a request that has not been sealed into a batch.
    ///
    /// Atomically updates `gateway:request:<request-id>`, removes the ID from its
    /// request queue, and deletes all `gateway:resource:<resource-id>` locks
    /// owned by the request. The transition is rejected unless its state is
    /// [`crate::storage::types::RequestState::Queued`].
    pub(crate) async fn fail_queued(
        &self,
        request_id: RequestId,
        reason: String,
        failed_at: Timestamp,
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

    use super::{AcceptRequestOutcome, RequestRepository};
    use crate::storage::{
        test_support::start_redis,
        types::{BatchKind, NewRequest, RequestId, RequestPayload, RequestState, ResourceLock},
    };

    const ACCEPTED_AT: u64 = 100;

    async fn connect_repository(redis_url: &str) -> RequestRepository {
        let client = redis::Client::open(redis_url).unwrap();
        let manager = ConnectionManager::new(client).await.unwrap();
        RequestRepository::new(manager)
    }

    fn operation_request(id: RequestId, account: u64) -> NewRequest {
        NewRequest {
            id,
            payload: RequestPayload::Operation(Bytes::from_static(&[1, 2, 3])),
            accepted_at: ACCEPTED_AT,
            resource_locks: vec![ResourceLock::Account(account)],
        }
    }

    #[tokio::test]
    async fn persists_complete_create_request() {
        let (redis_url, _redis) = start_redis().await;
        let repository = connect_repository(&redis_url).await;
        let id = RequestId(Uuid::new_v4());
        let authenticator = address!("1111111111111111111111111111111111111111");
        let request = NewRequest {
            id,
            payload: RequestPayload::CreateAccount(CreateAccountRequest {
                recovery_address: None,
                authenticator_addresses: vec![authenticator],
                authenticator_pubkeys: vec![U256::from(10)],
                offchain_signer_commitment: U256::from(20),
            }),
            accepted_at: ACCEPTED_AT,
            resource_locks: vec![ResourceLock::Authenticator(authenticator)],
        };

        assert_eq!(
            repository.accept(request).await.unwrap(),
            AcceptRequestOutcome::Accepted
        );
        let stored = repository.load(id).await.unwrap().unwrap();

        assert_eq!(stored.id, id);
        assert_eq!(stored.state, RequestState::Queued);
        assert_eq!(stored.accepted_at, ACCEPTED_AT);
        assert_eq!(stored.updated_at, ACCEPTED_AT);
        assert_eq!(
            stored.resource_locks,
            vec![ResourceLock::Authenticator(authenticator)]
        );
        let RequestPayload::CreateAccount(payload) = stored.payload else {
            panic!("expected create-account payload");
        };
        assert_eq!(payload.authenticator_addresses, vec![authenticator]);
        assert_eq!(payload.authenticator_pubkeys, vec![U256::from(10)]);
        assert_eq!(payload.offchain_signer_commitment, U256::from(20));
        assert_eq!(
            repository
                .queue_len(BatchKind::CreateAccounts)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repository.queue_len(BatchKind::Operations).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn lock_contention_does_not_persist_or_enqueue_request() {
        let (redis_url, _redis) = start_redis().await;
        let repository = connect_repository(&redis_url).await;
        let first_id = RequestId(Uuid::new_v4());
        let blocked_id = RequestId(Uuid::new_v4());

        assert_eq!(
            repository
                .accept(operation_request(first_id, 42))
                .await
                .unwrap(),
            AcceptRequestOutcome::Accepted
        );
        assert_eq!(
            repository
                .accept(operation_request(blocked_id, 42))
                .await
                .unwrap(),
            AcceptRequestOutcome::ResourceLocked(ResourceLock::Account(42))
        );

        assert!(repository.load(blocked_id).await.unwrap().is_none());
        assert_eq!(
            repository.queue_len(BatchKind::Operations).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn load_many_preserves_order_and_missing_records() {
        let (redis_url, _redis) = start_redis().await;
        let repository = connect_repository(&redis_url).await;
        let first_id = RequestId(Uuid::new_v4());
        let missing_id = RequestId(Uuid::new_v4());
        let second_id = RequestId(Uuid::new_v4());
        repository
            .accept(operation_request(first_id, 1))
            .await
            .unwrap();
        repository
            .accept(operation_request(second_id, 2))
            .await
            .unwrap();

        let loaded = repository
            .load_many(&[second_id, missing_id, first_id])
            .await
            .unwrap();

        assert_eq!(loaded[0].as_ref().unwrap().id, second_id);
        assert!(loaded[1].is_none());
        assert_eq!(loaded[2].as_ref().unwrap().id, first_id);
        assert!(repository.load_many(&[]).await.unwrap().is_empty());
    }
}
