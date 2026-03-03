use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::{AsyncTypedCommands, Client, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use world_id_core::api_types::{GatewayErrorCode, GatewayRequestKind, GatewayRequestState};

use crate::{
    batch_policy::BacklogUrgencyStats,
    config::RateLimitConfig,
    error::{GatewayErrorResponse, GatewayResult},
};
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRecord {
    pub kind: GatewayRequestKind,
    pub status: GatewayRequestState,
    pub updated_at: u64,
    #[serde(default)]
    pub inflight_keys: Vec<String>,
}

const REQUESTS_TTL: Duration = Duration::from_secs(86_400); // 24 hours
/// TTL for in-flight authenticator addresses (5 minutes safety fallback).
const INFLIGHT_TTL: Duration = Duration::from_secs(300);
const PENDING_SET_KEY: &str = "gateway:pending_requests";

/// Scope used to compute queued backlog stats for a specific batcher.
#[derive(Clone, Copy, Debug)]
pub enum BacklogScope {
    /// Include all request kinds.
    All,
    /// Include only create-account requests.
    Create,
    /// Include only ops requests (insert/update/remove/recover).
    Ops,
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Global request tracker instance.
///
/// Tracks all requests made to the gateway by ID for async querying.
/// Also tracks in-flight authenticator addresses to prevent duplicate requests.
/// Includes rate limiting for leaf_index-based requests.
///
/// Uses Redis for persistent, multi-node request storage.
#[derive(Clone)]
pub struct RequestTracker {
    /// The Redis connection manager.
    redis_manager: ConnectionManager,
    /// Rate limiting configuration, if enabled.
    rate_limit: Option<RateLimitConfig>,
}

impl RequestTracker {
    /// Initializes the request tracker instance.
    ///
    /// # Panics
    /// If the connection to Redis fails.
    pub async fn new(redis_url: String, rate_limit: Option<RateLimitConfig>) -> Self {
        let client = Client::open(redis_url.as_str()).expect("Unable to connect to Redis");
        let redis_manager = ConnectionManager::new(client)
            .await
            .expect("Unable to create Redis connection manager");

        tracing::info!("Connection to Redis established");

        Self {
            redis_manager,
            rate_limit,
        }
    }

    /// Returns the Redis key for a request record.
    fn request_key(id: &str) -> String {
        format!("gateway:request:{}", id)
    }

    /// Returns the Redis key for an in-flight lock given a raw identifier.
    fn inflight_redis_key(kind: GatewayRequestKind, raw: &str) -> String {
        let tag = match kind {
            GatewayRequestKind::CreateAccount => "auth",
            _ => "leaf",
        };
        format!("gateway:inflight:{tag}:{raw}")
    }

    /// Creates a new request with a specific ID, atomically acquiring in-flight
    /// lock keys via `SET NX`.
    ///
    /// If any inflight key already exists, the entire operation is aborted and a
    /// `DuplicateRequestInFlight` error is returned. On success, both the request
    /// record and all inflight keys are guaranteed to exist in Redis.
    pub async fn new_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
        inflight_keys: Vec<String>,
    ) -> Result<(), GatewayErrorResponse> {
        let redis_inflight_keys: Vec<String> = inflight_keys
            .iter()
            .map(|raw| Self::inflight_redis_key(kind, raw))
            .collect();

        let record = RequestRecord {
            kind,
            status: GatewayRequestState::Queued,
            updated_at: now_unix_secs(),
            inflight_keys: redis_inflight_keys.clone(),
        };

        let mut manager = self.redis_manager.clone();
        let key = Self::request_key(&id);
        let json_str = serde_json::to_string(&record).map_err(|e| {
            tracing::error!("FATAL: unable to serialize a RequestRecord: {e}");
            GatewayErrorResponse::internal_server_error()
        })?;

        // KEYS: [request_key, pending_set_key, inflight_key_1, ..., inflight_key_N]
        // ARGV: [record_json, request_ttl, request_id, inflight_ttl]
        let script = r#"
            -- KEYS: [request_key, pending_set_key, inflight_key_1, ..., inflight_key_N]
            local inflight_start = 3
            local inflight_ttl = tonumber(ARGV[4])

            -- Atomically check if any inflight key already exists
            -- When the any key exists, return it immediately.
            for i = inflight_start, #KEYS do
                if redis.call('EXISTS', KEYS[i]) == 1 then
                    return KEYS[i]
                end
            end

            -- Set all inflight keys
            for i = inflight_start, #KEYS do
                redis.call('SET', KEYS[i], '1', 'EX', inflight_ttl)
            end

            -- Create the request record if record for this ID does not exist
            local ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
            if not ok then
                -- Rollback inflight keys
                for i = inflight_start, #KEYS do
                    redis.call('DEL', KEYS[i])
                end
                return redis.error_reply('request already exists')
            end

            -- Add the request ID to the pending set
            redis.call('SADD', KEYS[2], ARGV[3])
            return nil
        "#;

        let script = redis::Script::new(script);
        let mut invocation = script.prepare_invoke();
        invocation.key(&key);
        invocation.key(PENDING_SET_KEY);
        for inflight_key in &redis_inflight_keys {
            invocation.key(inflight_key);
        }
        invocation.arg(&json_str);
        invocation.arg(REQUESTS_TTL.as_secs());
        invocation.arg(&id);
        invocation.arg(INFLIGHT_TTL.as_secs());

        let result: Result<Option<String>, redis::RedisError> =
            invocation.invoke_async(&mut manager).await;

        match result {
            Ok(None) => Ok(()),
            Ok(Some(duplicate_key)) => {
                tracing::info!(
                    key = %duplicate_key,
                    "Duplicate in-flight request detected"
                );
                Err(GatewayErrorResponse::bad_request(
                    GatewayErrorCode::DuplicateRequestInFlight,
                ))
            }
            Err(e) => {
                tracing::error!("Error creating request {id}: {e}");
                Err(GatewayErrorResponse::internal_server_error())
            }
        }
    }

    /// Updates the status of multiple requests in a batch.
    pub async fn set_status_batch(&self, ids: &[String], status: GatewayRequestState) {
        for id in ids {
            if let Err(e) = self.set_status_on_redis(id, &status).await {
                tracing::error!("Error updating status for request {id}: {e}");
            }
        }
    }

    /// Updates the status of a single request.
    pub async fn set_status(&self, id: &str, status: GatewayRequestState) {
        self.set_status_batch(&[id.to_string()], status).await;
    }

    /// Resolves a batch of requests based on a transaction receipt outcome.
    ///
    /// If the receipt indicates success, marks all requests as `Finalized`.
    /// If the receipt indicates a revert, marks all requests as `Failed`.
    pub async fn finalize_from_receipt(
        &self,
        ids: &[String],
        receipt_succeeded: bool,
        tx_hash: &str,
    ) {
        let status = if receipt_succeeded {
            GatewayRequestState::Finalized {
                tx_hash: tx_hash.to_string(),
            }
        } else {
            GatewayRequestState::failed(
                format!("transaction reverted on-chain (tx: {tx_hash})"),
                Some(GatewayErrorCode::TransactionReverted),
            )
        };
        self.set_status_batch(ids, status).await;
    }

    /// Returns a snapshot of the current state of a request, if it exists.
    pub async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        let mut manager = self.redis_manager.clone();
        let key = Self::request_key(id);
        let result: Result<Option<String>, redis::RedisError> = manager.get(&key).await;

        match result {
            Ok(Some(json_str)) => match serde_json::from_str::<RequestRecord>(&json_str) {
                Ok(record) => Some(record),
                Err(e) => {
                    tracing::error!("Failed to deserialize request from Redis: {}", e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Failed to get request from Redis: {}", e);
                None
            }
        }
    }

    /// Sets the status of a specific request in Redis.
    ///
    /// Atomically updates the status and `updated_at` timestamp. When the new
    /// status is terminal (`finalized` or `failed`), the request ID is also
    /// removed from the pending set in the same Lua script invocation.
    async fn set_status_on_redis(
        &self,
        id: &str,
        status: &GatewayRequestState,
    ) -> GatewayResult<()> {
        let mut manager = self.redis_manager.clone();
        let key = Self::request_key(id);
        let status_json = serde_json::to_string(status)?;
        let now = now_unix_secs();

        let script = r#"
            local record = redis.call('GET', KEYS[1])
            if not record then
                return redis.error_reply('attempted to update inexistent request')
            end

            local decoded = cjson.decode(record)
            decoded.status = cjson.decode(ARGV[1])
            decoded.updated_at = tonumber(ARGV[2])
            if decoded.inflight_keys and #decoded.inflight_keys == 0 then
                setmetatable(decoded.inflight_keys, cjson.empty_array_mt)
            end
            local updated = cjson.encode(decoded)

            redis.call('SET', KEYS[1], updated, 'KEEPTTL')

            -- If the request is finalized or failed, remove it from the pending set
            -- and atomically clean up any associated in-flight lock keys.
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
        "#;

        let result: Result<(), redis::RedisError> = redis::Script::new(script)
            .key(&key)
            .key(PENDING_SET_KEY)
            .arg(&status_json)
            .arg(now)
            .arg(id)
            .invoke_async(&mut manager)
            .await;

        result?;
        Ok(())
    }

    // =========================================================================
    // Pending-set helpers (used by orphan_sweeper)
    // =========================================================================

    /// Returns all request IDs currently in the pending set.
    pub async fn get_pending_requests(&self) -> GatewayResult<Vec<String>> {
        let mut manager = self.redis_manager.clone();
        let ids: std::collections::HashSet<String> = manager.smembers(PENDING_SET_KEY).await?;
        Ok(ids.into_iter().collect())
    }

    /// Fetches multiple request records in a single `MGET` round-trip.
    pub async fn snapshot_batch(
        &self,
        ids: &[String],
    ) -> GatewayResult<Vec<(String, Option<RequestRecord>)>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let keys: Vec<String> = ids.iter().map(|id| Self::request_key(id)).collect();
        let mut manager = self.redis_manager.clone();

        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut manager)
            .await?;

        Ok(ids
            .iter()
            .zip(values)
            .map(|(id, maybe_json)| {
                let record = maybe_json.and_then(|json_str| {
                    serde_json::from_str::<RequestRecord>(&json_str)
                        .map_err(|e| {
                            tracing::error!("Failed to deserialize request {id} from Redis: {e}");
                        })
                        .ok()
                });
                (id.clone(), record)
            })
            .collect())
    }

    /// Computes queued-backlog urgency statistics from pending requests.
    ///
    /// The stats are based only on requests currently in `Queued` state.
    pub async fn queued_backlog_stats(&self) -> GatewayResult<BacklogUrgencyStats> {
        self.queued_backlog_stats_for_scope(BacklogScope::All).await
    }

    /// Computes queued-backlog urgency statistics from pending requests in a given scope.
    ///
    /// The stats are based only on requests currently in `Queued` state and whose
    /// [`GatewayRequestKind`] belongs to `scope`.
    pub async fn queued_backlog_stats_for_scope(
        &self,
        scope: BacklogScope,
    ) -> GatewayResult<BacklogUrgencyStats> {
        let ids = self.get_pending_requests().await?;
        if ids.is_empty() {
            return Ok(BacklogUrgencyStats::default());
        }

        let records = self.snapshot_batch(&ids).await?;
        let now = now_unix_secs();
        let mut queued_count = 0usize;
        let mut oldest_age_secs = 0u64;
        for (_, maybe_record) in records {
            let Some(record) = maybe_record else {
                continue;
            };
            if !matches_scope(record.kind, scope) {
                continue;
            }
            if matches!(record.status, GatewayRequestState::Queued) {
                let age = now.saturating_sub(record.updated_at);
                queued_count += 1;
                oldest_age_secs = oldest_age_secs.max(age);
            }
        }

        if queued_count == 0 {
            return Ok(BacklogUrgencyStats::default());
        }

        Ok(BacklogUrgencyStats {
            queued_count,
            oldest_age_secs,
        })
    }

    /// Removes a request ID from the pending set (safety-net cleanup).
    pub async fn remove_from_pending_set(&self, id: &str) {
        let mut manager = self.redis_manager.clone();
        let result: Result<usize, redis::RedisError> = manager.srem(PENDING_SET_KEY, id).await;
        if let Err(e) = result {
            tracing::error!("Failed to SREM {id} from pending set: {e}");
        }
    }

    // =========================================================================
    // Rate limiting
    // =========================================================================

    /// Returns the Redis key for a rate limit entry.
    fn rate_limit_key(leaf_index: u64) -> String {
        format!("gateway:ratelimit:leaf:{}", leaf_index)
    }

    /// Checks if a request for the given leaf_index should be allowed.
    ///
    /// Returns `Ok(())` if the request is allowed.
    /// Returns `Err(GatewayErrorResponse)` with rate limit error if exceeded.
    ///
    /// If rate limiting is not configured, always returns `Ok(())`.
    pub async fn check_rate_limit(
        &self,
        leaf_index: u64,
        request_id: &str,
    ) -> Result<(), GatewayErrorResponse> {
        let Some(ref rl) = self.rate_limit else {
            return Ok(());
        };
        let (window_secs, max_requests) = (rl.window_secs, rl.max_requests);

        let key = Self::rate_limit_key(leaf_index);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let mut manager = self.redis_manager.clone();

        let script = redis::Script::new(
            r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local request_id = ARGV[4]

            -- Remove old entries outside the window
            local min_timestamp = now - window
            redis.call('ZREMRANGEBYSCORE', key, '-inf', min_timestamp)

            -- Count current entries in the window
            local current = redis.call('ZCARD', key)

            -- Check if we're under the limit
            if current < limit then
                -- Add the new request with current timestamp as score
                redis.call('ZADD', key, now, request_id)
                -- Set expiration on the key to cleanup old keys
                redis.call('EXPIRE', key, window)
                return current + 1
            else
                -- Rate limit exceeded
                return -1
            end
            "#,
        );
        let result: Result<i64, redis::RedisError> = script
            .key(&key)
            .arg(now)
            .arg(window_secs)
            .arg(max_requests)
            .arg(request_id)
            .invoke_async(&mut manager)
            .await;

        match result {
            Ok(-1) => {
                tracing::warn!(
                    leaf_index = leaf_index,
                    request_id = request_id,
                    "Rate limit exceeded"
                );
                Err(GatewayErrorResponse::rate_limit_exceeded(
                    window_secs,
                    max_requests,
                ))
            }
            Ok(count) => {
                tracing::debug!(
                    leaf_index = leaf_index,
                    request_id = request_id,
                    count = count,
                    max = max_requests,
                    "Rate limit check passed"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!("Redis error during rate limit check: {}", e);
                tracing::warn!("Rate limit check failed due to Redis error, allowing request");
                Ok(())
            }
        }
    }
}

fn matches_scope(kind: GatewayRequestKind, scope: BacklogScope) -> bool {
    match scope {
        BacklogScope::All => true,
        BacklogScope::Create => matches!(kind, GatewayRequestKind::CreateAccount),
        BacklogScope::Ops => matches!(
            kind,
            GatewayRequestKind::InsertAuthenticator
                | GatewayRequestKind::UpdateAuthenticator
                | GatewayRequestKind::RemoveAuthenticator
                | GatewayRequestKind::RecoverAccount
        ),
    }
}
