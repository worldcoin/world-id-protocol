use std::time::Duration;

use alloy::primitives::Address;
use redis::{AsyncTypedCommands, Client, SetExpiry, SetOptions, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use world_id_core::api_types::{GatewayErrorCode, GatewayRequestKind, GatewayRequestState};

use crate::error::{GatewayErrorResponse, GatewayResult};
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRecord {
    pub kind: GatewayRequestKind,
    pub status: GatewayRequestState,
}

const REQUESTS_TTL: Duration = Duration::from_secs(86_400); // 24 hours
/// TTL for in-flight authenticator addresses (5 minutes safety fallback).
const INFLIGHT_TTL: Duration = Duration::from_secs(300);

/// Global request tracker instance.
///
/// Tracks all requests made to the gateway by ID for async querying.
/// Also tracks in-flight authenticator addresses to prevent duplicate requests.
///
/// Uses Redis for persistent, multi-node request storage.
#[derive(Clone)]
pub struct RequestTracker {
    /// The Redis connection manager.
    redis_manager: ConnectionManager,
}

impl RequestTracker {
    /// Initializes the request tracker instance.
    ///
    /// # Panics
    /// If the connection to Redis fails.
    pub async fn new(redis_url: String) -> Self {
        let client = Client::open(redis_url.as_str()).expect("Unable to connect to Redis");
        let redis_manager = ConnectionManager::new(client)
            .await
            .expect("Unable to create Redis connection manager");

        tracing::info!("Connection to Redis established");

        Self { redis_manager }
    }

    /// Returns the Redis key for a request record.
    fn request_key(id: &str) -> String {
        format!("gateway:request:{}", id)
    }

    /// Creates a new request with a specific ID.
    pub async fn new_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
    ) -> Result<(), GatewayErrorResponse> {
        let record = RequestRecord {
            kind,
            status: GatewayRequestState::Queued,
        };

        let mut manager = self.redis_manager.clone();
        let key = Self::request_key(&id);
        let json_str = serde_json::to_string(&record).map_err(|e| {
            tracing::error!("FATAL: unable to serialize a RequestRecord: {e}");
            GatewayErrorResponse::internal_server_error()
        })?;

        let opts = SetOptions::default()
            .conditional_set(redis::ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(REQUESTS_TTL.as_secs()));

        manager
            .set_options(&key, json_str, opts)
            .await
            .map_err(handle_redis_error)?;

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
    async fn set_status_on_redis(
        &self,
        id: &str,
        status: &GatewayRequestState,
    ) -> GatewayResult<()> {
        let mut manager = self.redis_manager.clone();
        let key = Self::request_key(id);
        let status_json = serde_json::to_string(status)?;

        let script = r#"
            local record = redis.call('GET', KEYS[1])
            if not record then
                return redis.error_reply('attempted to update inexistent request')
            end

            local decoded = cjson.decode(record)
            decoded.status = cjson.decode(ARGV[1])
            local updated = cjson.encode(decoded)

            redis.call('SET', KEYS[1], updated, 'KEEPTTL')
            return redis.status_reply('OK')
        "#;

        let result: Result<(), redis::RedisError> = redis::Script::new(script)
            .key(&key)
            .arg(&status_json)
            .invoke_async(&mut manager)
            .await;

        result?;
        Ok(())
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
}

/// Converts a Redis error into a gateway error response.
fn handle_redis_error(e: redis::RedisError) -> GatewayErrorResponse {
    tracing::error!("Unhandled Redis error: {}", e);
    GatewayErrorResponse::internal_server_error()
}
