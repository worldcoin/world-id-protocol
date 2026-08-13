use redis::aio::ConnectionManager;

use crate::{
    error::GatewayResult,
    storage::types::{BatchKind, NewRequest, RequestId, ResourceLock, StoredRequest, Timestamp},
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
        unimplemented!()
    }

    /// Persists a queued request and acquires all of its resource locks.
    ///
    /// Atomically creates `gateway:request:<request-id>`, adds the ID to
    /// `gateway:requests:create` or `gateway:requests:ops`, and creates each
    /// `gateway:resource:<resource-id>` lock. If any lock exists, returns
    /// [`AcceptRequestOutcome::ResourceLocked`] without changing storage.
    pub(crate) async fn accept(&self, request: NewRequest) -> GatewayResult<AcceptRequestOutcome> {
        unimplemented!()
    }

    /// Loads one request from `gateway:request:<request-id>`.
    ///
    /// Returns `None` when the record does not exist. Queue indexes and resource
    /// locks are not consulted.
    pub(crate) async fn load(&self, request_id: RequestId) -> GatewayResult<Option<StoredRequest>> {
        unimplemented!()
    }

    /// Loads request records from `gateway:request:<request-id>` in one round trip.
    ///
    /// Results preserve input order, including `None` for every missing record.
    pub(crate) async fn load_many(
        &self,
        request_ids: &[RequestId],
    ) -> GatewayResult<Vec<Option<StoredRequest>>> {
        unimplemented!()
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
        unimplemented!()
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
