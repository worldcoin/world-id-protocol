use std::{collections::HashSet, time::Duration};

use redis::{AsyncTypedCommands, Client, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use world_id_primitives::api_types::{GatewayRequestKind, GatewayRequestState};

use crate::error::GatewayResult;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRecord {
    pub kind: GatewayRequestKind,
    pub status: GatewayRequestState,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inflight_keys: Vec<String>,
}

const REQUESTS_TTL: Duration = Duration::from_secs(86_400);
const INFLIGHT_TTL: Duration = Duration::from_secs(300);
const PENDING_SET_KEY: &str = "gateway:pending_requests";

/// Result of atomically creating a tracked request and acquiring its locks.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CreateRequestOutcome {
    /// The request record, pending-set entry, and in-flight locks were created.
    Created,
    /// An in-flight lock already existed, so nothing was created.
    DuplicateInflight(String),
}

/// Result of checking and recording a request against a rate-limit window.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RateLimitOutcome {
    /// The request was recorded; the value is the current count in the window.
    Allowed(u64),
    /// The request was not recorded because the configured limit was reached.
    Exceeded,
}

/// Persistent storage for gateway request tracking.
///
/// This module owns the Redis schema, commands, scripts, TTLs, and JSON
/// serialization. Callers operate on request-tracking concepts only.
#[derive(Clone)]
pub(crate) struct RequestStore {
    manager: ConnectionManager,
}

impl RequestStore {
    /// Connects to Redis and creates a cloneable connection manager.
    ///
    /// # Panics
    ///
    /// Panics if `redis_url` is invalid or the initial connection cannot be
    /// established.
    pub(crate) async fn connect(redis_url: &str) -> Self {
        let client = Client::open(redis_url).expect("Unable to connect to Redis");
        let manager = ConnectionManager::new(client)
            .await
            .expect("Unable to create Redis connection manager");

        tracing::info!("Connection to Redis established");
        Self { manager }
    }

    /// Stores a terminal request record without adding pending or in-flight entries.
    ///
    /// The record expires after [`REQUESTS_TTL`]. If `id` already exists, the
    /// existing record is preserved.
    pub(crate) async fn create_terminal_request(
        &self,
        id: &str,
        kind: GatewayRequestKind,
        status: GatewayRequestState,
        updated_at: u64,
    ) -> GatewayResult<()> {
        let record = RequestRecord {
            kind,
            status,
            updated_at,
            inflight_keys: Vec::new(),
        };
        let json = serde_json::to_string(&record)?;
        let mut manager = self.manager.clone();

        let _: () = redis::cmd("SET")
            .arg(Self::request_key(id))
            .arg(json)
            .arg("NX")
            .arg("EX")
            .arg(REQUESTS_TTL.as_secs())
            .query_async(&mut manager)
            .await?;
        Ok(())
    }

    /// Atomically creates a queued request, pending entry, and in-flight locks.
    ///
    /// Returns [`CreateRequestOutcome::DuplicateInflight`] without changing
    /// storage when any requested lock already exists. The request record uses
    /// [`REQUESTS_TTL`], while lock entries use [`INFLIGHT_TTL`].
    pub(crate) async fn create_request(
        &self,
        id: &str,
        kind: GatewayRequestKind,
        inflight_keys: &[String],
        updated_at: u64,
    ) -> GatewayResult<CreateRequestOutcome> {
        let redis_inflight_keys: Vec<String> = inflight_keys
            .iter()
            .map(|raw| Self::inflight_key(kind, raw))
            .collect();
        let record = RequestRecord {
            kind,
            status: GatewayRequestState::Queued,
            updated_at,
            inflight_keys: redis_inflight_keys.clone(),
        };
        let json = serde_json::to_string(&record)?;
        let mut manager = self.manager.clone();

        let script = redis::Script::new(
            r#"
            local inflight_start = 3
            local inflight_ttl = tonumber(ARGV[4])

            for i = inflight_start, #KEYS do
                if redis.call('EXISTS', KEYS[i]) == 1 then
                    return KEYS[i]
                end
            end

            for i = inflight_start, #KEYS do
                redis.call('SET', KEYS[i], '1', 'EX', inflight_ttl)
            end

            local ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
            if not ok then
                for i = inflight_start, #KEYS do
                    redis.call('DEL', KEYS[i])
                end
                return redis.error_reply('request already exists')
            end

            redis.call('SADD', KEYS[2], ARGV[3])
            return nil
            "#,
        );
        let mut invocation = script.prepare_invoke();
        invocation.key(Self::request_key(id));
        invocation.key(PENDING_SET_KEY);
        for key in &redis_inflight_keys {
            invocation.key(key);
        }
        invocation.arg(json);
        invocation.arg(REQUESTS_TTL.as_secs());
        invocation.arg(id);
        invocation.arg(INFLIGHT_TTL.as_secs());

        let duplicate: Option<String> = invocation.invoke_async(&mut manager).await?;
        Ok(match duplicate {
            Some(key) => CreateRequestOutcome::DuplicateInflight(key),
            None => CreateRequestOutcome::Created,
        })
    }

    /// Loads and deserializes one request record by ID.
    ///
    /// Returns `Ok(None)` when the record does not exist.
    pub(crate) async fn request(&self, id: &str) -> GatewayResult<Option<RequestRecord>> {
        let mut manager = self.manager.clone();
        let json: Option<String> = manager.get(Self::request_key(id)).await?;
        json.map(|json| serde_json::from_str(&json).map_err(Into::into))
            .transpose()
    }

    /// Atomically updates a request's status and timestamp while preserving its TTL.
    ///
    /// Terminal statuses also remove the request from the pending set and delete
    /// its in-flight locks. Returns an error when the request does not exist.
    pub(crate) async fn update_status(
        &self,
        id: &str,
        status: &GatewayRequestState,
        updated_at: u64,
    ) -> GatewayResult<()> {
        let status_json = serde_json::to_string(status)?;
        let mut manager = self.manager.clone();

        let _: () = redis::Script::new(
            r#"
            local record = redis.call('GET', KEYS[1])
            if not record then
                return redis.error_reply('attempted to update inexistent request')
            end

            local decoded = cjson.decode(record)
            decoded.status = cjson.decode(ARGV[1])
            decoded.updated_at = tonumber(ARGV[2])
            local updated = cjson.encode(decoded)

            redis.call('SET', KEYS[1], updated, 'KEEPTTL')

            local state = decoded.status.state
            if state == 'finalized' or state == 'failed' then
                redis.call('SREM', KEYS[2], ARGV[3])
                local inflight = decoded.inflight_keys
                if inflight then
                    for _, k in ipairs(inflight) do
                        redis.call('DEL', k)
                    end
                end
            end

            return redis.status_reply('OK')
            "#,
        )
        .key(Self::request_key(id))
        .key(PENDING_SET_KEY)
        .arg(status_json)
        .arg(updated_at)
        .arg(id)
        .invoke_async(&mut manager)
        .await?;
        Ok(())
    }

    /// Returns every request ID in the pending set.
    ///
    /// The returned order is unspecified.
    pub(crate) async fn pending_request_ids(&self) -> GatewayResult<Vec<String>> {
        let mut manager = self.manager.clone();
        let ids: HashSet<String> = manager.smembers(PENDING_SET_KEY).await?;
        Ok(ids.into_iter().collect())
    }

    /// Loads multiple request records in one Redis round trip.
    ///
    /// Results preserve the order of `ids`. Missing or malformed records are
    /// represented as `None`; malformed records are also logged.
    pub(crate) async fn requests(
        &self,
        ids: &[String],
    ) -> GatewayResult<Vec<(String, Option<RequestRecord>)>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let keys: Vec<String> = ids.iter().map(|id| Self::request_key(id)).collect();
        let mut manager = self.manager.clone();
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(keys)
            .query_async(&mut manager)
            .await?;

        Ok(ids
            .iter()
            .zip(values)
            .map(|(id, json)| {
                let record = json.and_then(|json| {
                    serde_json::from_str(&json)
                        .map_err(|error| {
                            tracing::error!(request_id = id, %error, "Failed to deserialize request from Redis");
                        })
                        .ok()
                });
                (id.clone(), record)
            })
            .collect())
    }

    /// Removes a request ID from the pending set.
    ///
    /// Succeeds when the ID was not present, making cleanup idempotent.
    pub(crate) async fn remove_pending_request(&self, id: &str) -> GatewayResult<()> {
        let mut manager = self.manager.clone();
        let _: usize = manager.srem(PENDING_SET_KEY, id).await?;
        Ok(())
    }

    /// Atomically checks and records a request in a leaf's sliding time window.
    ///
    /// Entries at or before `now - window_secs` are removed before counting.
    /// Allowed requests are inserted with `request_id` as the sorted-set member;
    /// rejected requests do not modify the current window after stale cleanup.
    pub(crate) async fn check_rate_limit(
        &self,
        leaf_index: u64,
        request_id: &str,
        now: u64,
        window_secs: u64,
        max_requests: u64,
    ) -> GatewayResult<RateLimitOutcome> {
        let mut manager = self.manager.clone();
        let count: i64 = redis::Script::new(
            r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local request_id = ARGV[4]

            local min_timestamp = now - window
            redis.call('ZREMRANGEBYSCORE', key, '-inf', min_timestamp)
            local current = redis.call('ZCARD', key)

            if current < limit then
                redis.call('ZADD', key, now, request_id)
                redis.call('EXPIRE', key, window)
                return current + 1
            else
                return -1
            end
            "#,
        )
        .key(Self::rate_limit_key(leaf_index))
        .arg(now)
        .arg(window_secs)
        .arg(max_requests)
        .arg(request_id)
        .invoke_async(&mut manager)
        .await?;

        Ok(if count == -1 {
            RateLimitOutcome::Exceeded
        } else {
            RateLimitOutcome::Allowed(count as u64)
        })
    }

    /// Returns the Redis key containing one serialized request record.
    fn request_key(id: &str) -> String {
        format!("gateway:request:{id}")
    }

    /// Returns the Redis key for an in-flight request lock.
    ///
    /// Account creation locks are scoped by authenticator address; all other
    /// request kinds are scoped by leaf index.
    fn inflight_key(kind: GatewayRequestKind, raw: &str) -> String {
        let tag = match kind {
            GatewayRequestKind::CreateAccount => "create",
            _ => "leaf",
        };
        format!("gateway:inflight:{tag}:{raw}")
    }

    /// Returns the Redis sorted-set key for one leaf's rate-limit window.
    fn rate_limit_key(leaf_index: u64) -> String {
        format!("gateway:ratelimit:leaf:{leaf_index}")
    }
}
