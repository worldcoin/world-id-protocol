use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use redis::{AsyncTypedCommands, Client, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use world_id_core::api_types::{GatewayErrorCode, GatewayRequestKind, GatewayRequestState};

use crate::{
    config::RateLimitConfig,
    error::{GatewayErrorResponse, GatewayResult},
};
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRecord {
    pub kind: GatewayRequestKind,
    pub status: GatewayRequestState,
    pub updated_at: u64,
}

const REQUESTS_TTL: Duration = Duration::from_secs(86_400); // 24 hours
/// TTL for in-flight authenticator addresses (5 minutes safety fallback).
const INFLIGHT_TTL: Duration = Duration::from_secs(300);
const PENDING_SET_KEY: &str = "gateway:pending_requests";

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
    rate_limit_config: Option<RateLimitConfig>,
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
            rate_limit_config,
        }
    }

    /// Returns the Redis key for a request record.
    fn request_key(id: &str) -> String {
        format!("gateway:request:{}", id)
    }

    /// Creates a new request with a specific ID.
    ///
    /// Expects the request ID to be unique, returns an error if it already exists.
    pub async fn new_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
    ) -> Result<(), GatewayErrorResponse> {
        let record = RequestRecord {
            kind,
            status: GatewayRequestState::Queued,
            updated_at: now_unix_secs(),
        };

        let mut manager = self.redis_manager.clone();
        let key = Self::request_key(&id);
        let json_str = serde_json::to_string(&record).map_err(|e| {
            tracing::error!("FATAL: unable to serialize a RequestRecord: {e}");
            GatewayErrorResponse::internal_server_error()
        })?;

        let script = r#"
            local ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
            if not ok then
                return redis.error_reply('request already exists')
            end

            -- Add the request ID to the pending set
            redis.call('SADD', KEYS[2], ARGV[3])
            return redis.status_reply('OK')
        "#;

        redis::Script::new(script)
            .key(&key)
            .key(PENDING_SET_KEY)
            .arg(&json_str)
            .arg(REQUESTS_TTL.as_secs())
            .arg(&id)
            .invoke_async::<()>(&mut manager)
            .await
            .map_err(|e| {
                tracing::error!("Error creating request {id}: {e}");
                GatewayErrorResponse::internal_server_error()
            })?;

        Ok(())
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
            local updated = cjson.encode(decoded)

            redis.call('SET', KEYS[1], updated, 'KEEPTTL')

            -- If the request is finalized or failed, remove it from the pending set
            local state = decoded.status.state
            if state == 'finalized' or state == 'failed' then
                redis.call('SREM', KEYS[2], ARGV[3])
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

    /// Removes a request ID from the pending set (safety-net cleanup).
    pub async fn remove_from_pending_set(&self, id: &str) {
        let mut manager = self.redis_manager.clone();
        let result: Result<usize, redis::RedisError> = manager.srem(PENDING_SET_KEY, id).await;
        if let Err(e) = result {
            tracing::error!("Failed to SREM {id} from pending set: {e}");
        }
    }

    // =========================================================================
    // In-flight authenticator address tracking
    // =========================================================================

    /// Redis key for an in-flight authenticator address.
    fn inflight_key(addr: &Address) -> String {
        format!("gateway:inflight:auth:{addr}")
    }

    /// Attempts to atomically insert all addresses as in-flight.
    ///
    /// Returns `Ok(())` if all addresses were successfully inserted.
    /// Returns `Err(GatewayErrorResponse)` with `DuplicateRequestInFlight` code if any address
    /// was already in-flight.
    /// Returns `Err(GatewayErrorResponse)` with internal server error if a Redis/infrastructure
    /// error occurred.
    ///
    /// If insertion fails partway through, already-inserted addresses are rolled back.
    pub async fn try_insert_inflight(
        &self,
        addresses: &[Address],
    ) -> Result<(), GatewayErrorResponse> {
        // Lua script that atomically:
        // 1. Checks if any key already exists
        // 2. If none exist, sets all keys with TTL
        // Returns nil on success, or the duplicate key on failure
        let script = redis::Script::new(
            r#"
            for i, key in ipairs(KEYS) do
                if redis.call('EXISTS', key) == 1 then
                    return key
                end
            end
            local ttl = tonumber(ARGV[1])
            for i, key in ipairs(KEYS) do
                redis.call('SET', key, '1', 'EX', ttl)
            end
            return nil
            "#,
        );

        let keys: Vec<String> = addresses.iter().map(Self::inflight_key).collect();
        let mut manager = self.redis_manager.clone();

        let mut invocation = script.prepare_invoke();
        for key in &keys {
            invocation.key(key);
        }
        invocation.arg(INFLIGHT_TTL.as_secs());

        let result: Result<Option<String>, redis::RedisError> =
            invocation.invoke_async(&mut manager).await;

        match result {
            Ok(None) => Ok(()),
            Ok(Some(duplicate_key)) => {
                tracing::warn!(
                    key = %duplicate_key,
                    "Duplicate in-flight request detected"
                );
                Err(GatewayErrorResponse::bad_request(
                    GatewayErrorCode::DuplicateRequestInFlight,
                ))
            }
            Err(e) => {
                tracing::error!("Redis error during in-flight insert: {e}");
                Err(GatewayErrorResponse::internal_server_error())
            }
        }
    }

    /// Remove all addresses from the in-flight tracker.
    pub async fn remove_inflight(&self, addresses: &[Address]) {
        let mut manager = self.redis_manager.clone();
        for addr in addresses {
            let key = Self::inflight_key(addr);
            let result: Result<usize, redis::RedisError> = manager.del(&key).await;
            if let Err(e) = result {
                tracing::error!("Failed to delete Redis key {key}: {e}");
            }
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
        let Some(ref rate_limit) = self.rate_limit else {
            return Ok(());
        };
        let (window_secs, max_requests) = (rate_limit.window_secs, rate_limit.max_requests);

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
