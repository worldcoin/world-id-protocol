use std::time::{Duration, Instant};

use alloy::primitives::Address;
use moka::{
    Expiry,
    future::Cache,
    ops::compute::{CompResult, Op},
};
use redis::{AsyncTypedCommands, Client, SetExpiry, SetOptions, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use world_id_core::types::{GatewayErrorResponse, GatewayRequestKind, GatewayRequestState};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRecord {
    pub kind: GatewayRequestKind,
    pub status: GatewayRequestState,
}

/// Error type for in-flight address insertion failures.
#[derive(Debug)]
pub enum InflightInsertError {
    /// An address was already in-flight (duplicate request).
    Duplicate(Address),
    /// An infrastructure error occurred (e.g., Redis failure).
    Infrastructure,
}

const REQUESTS_TTL: Duration = Duration::from_secs(86_400); // 24 hours
const CACHE_MAX_CAPACITY: u64 = 100_000;
/// TTL for in-flight authenticator addresses (5 minutes safety fallback).
const INFLIGHT_TTL: Duration = Duration::from_secs(300);

/// Custom expiry policy that preserves TTL on updates (like Redis KEEPTTL).
struct RequestExpiry;

impl Expiry<String, RequestRecord> for RequestExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        _value: &RequestRecord,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(REQUESTS_TTL)
    }

    fn expire_after_read(
        &self,
        _key: &String,
        _value: &RequestRecord,
        _read_at: Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        // Preserve original TTL on read
        duration_until_expiry
    }

    fn expire_after_update(
        &self,
        _key: &String,
        _value: &RequestRecord,
        _updated_at: Instant,
        duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        // Preserve original TTL on update (like Redis KEEPTTL)
        duration_until_expiry
    }
}

/// Global request tracker instance.
///
/// Tracks all requests made to the gateway by ID for async querying.
/// Also tracks in-flight authenticator addresses to prevent duplicate requests.
///
/// Using Redis is strongly recommended for production environments, and especially multi-node setups.
#[derive(Clone)]
pub struct RequestTracker {
    /// The lru cache with TTL-based expiration for request records.
    cache: Cache<String, RequestRecord>,
    /// Local cache for in-flight authenticator addresses (single-instance fallback).
    inflight_cache: Cache<Address, ()>,
    /// The db (redis) connection.
    redis_manager: Option<ConnectionManager>,
}

impl RequestTracker {
    /// Initializes the request tracker instance.
    ///
    /// # Panics
    /// If a Redis URL is provided but the connection to Redis fails.
    pub async fn new(redis_url: Option<String>) -> Self {
        let redis_manager = if let Some(url) = redis_url {
            let client = Client::open(url.as_str()).expect("Unable to connect to Redis");
            let manager = ConnectionManager::new(client)
                .await
                .expect("Unable to create Redis connection manager");

            tracing::info!("Connection to Redis established");

            Some(manager)
        } else {
            tracing::info!("No Redis URL provided, using in-memory request storage only");
            None
        };

        // Build moka cache with custom expiry that preserves TTL on updates
        let cache = Cache::builder()
            .max_capacity(CACHE_MAX_CAPACITY)
            .expire_after(RequestExpiry)
            .build();

        // Build moka cache for in-flight authenticator addresses
        let inflight_cache = Cache::builder().time_to_live(INFLIGHT_TTL).build();

        Self {
            cache,
            inflight_cache,
            redis_manager,
        }
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

        if let Some(mut manager) = self.redis_manager.clone() {
            // Persist to redis if configured
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
        } else {
            // No Redis, use local cache as storage
            self.cache.insert(id.clone(), record.clone()).await;
        }

        Ok(())
    }

    /// Updates the status of multiple requests in a batch.
    pub async fn set_status_batch(&self, ids: &[String], status: GatewayRequestState) {
        for id in ids {
            if self.redis_manager.is_some() {
                // Update redis if configured
                if let Err(e) = self.set_status_on_redis(id, &status).await {
                    tracing::error!("Error updating status for request {id}: {e}");
                }
            } else {
                // No Redis, update local cache
                self.cache
                    .entry_by_ref(id)
                    .and_compute_with(|entry| async {
                        match entry {
                            Some(entry) => {
                                let mut record = entry.into_value();
                                record.status = status.clone();
                                Op::Put(record)
                            }
                            None => Op::Nop,
                        }
                    })
                    .await;
            }
        }
    }

    /// Updates the status of a single request.
    pub async fn set_status(&self, id: &str, status: GatewayRequestState) {
        self.set_status_batch(&[id.to_string()], status).await;
    }

    /// Returns a snapshot of the current state of a request, if it exists.
    pub async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        if let Some(mut manager) = self.redis_manager.clone() {
            // Read from redis if configured
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
        } else {
            // No Redis, read from local cache
            self.cache.get(id).await
        }
    }

    /// Sets the status of a specific request in Redis.
    async fn set_status_on_redis(
        &self,
        id: &str,
        status: &GatewayRequestState,
    ) -> anyhow::Result<()> {
        if let Some(mut manager) = self.redis_manager.clone() {
            let key = Self::request_key(id);
            let status_json = serde_json::to_string(status)?;

            // Use Lua script for atomic read-modify-write to prevent race conditions
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
            return Ok(());
        }

        anyhow::bail!("Cannot call set_status_redis if Redis is not configured.")
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
    /// Returns `Err(InflightInsertError::Duplicate(addr))` if any address was already in-flight.
    /// Returns `Err(InflightInsertError::Infrastructure)` if a Redis/infrastructure error occurred.
    ///
    /// If insertion fails partway through, already-inserted addresses are rolled back.
    pub async fn try_insert_inflight(
        &self,
        addresses: &[Address],
    ) -> Result<(), InflightInsertError> {
        if let Some(manager) = &self.redis_manager {
            self.try_insert_inflight_redis(manager.clone(), addresses)
                .await
        } else {
            self.try_insert_inflight_local(addresses).await
        }
    }

    /// Remove all addresses from the in-flight tracker.
    pub async fn remove_inflight(&self, addresses: &[Address]) {
        if let Some(manager) = &self.redis_manager {
            self.remove_inflight_redis(manager.clone(), addresses).await;
        } else {
            self.remove_inflight_local(addresses).await;
        }
    }

    /// Attempts to insert all addresses into Redis using `SET NX` for atomicity.
    /// Returns `Err(Duplicate(addr))` if any address already exists, rolling back prior insertions.
    /// Returns `Err(Infrastructure)` if a Redis error occurs.
    async fn try_insert_inflight_redis(
        &self,
        mut manager: ConnectionManager,
        addresses: &[Address],
    ) -> Result<(), InflightInsertError> {
        let mut inserted_keys: Vec<String> = Vec::new();

        for addr in addresses {
            let key = Self::inflight_key(addr);

            // SET NX with TTL - only sets if key doesn't exist
            let opts = SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(SetExpiry::EX(INFLIGHT_TTL.as_secs()));

            let result: Result<Option<String>, redis::RedisError> =
                manager.set_options(&key, "1", opts).await;

            match result {
                Ok(Some(_)) => {
                    // Successfully inserted
                    inserted_keys.push(key);
                }
                Ok(None) => {
                    // Key already exists - rollback and return duplicate error
                    self.rollback_inflight_redis(&mut manager, &inserted_keys)
                        .await;
                    return Err(InflightInsertError::Duplicate(*addr));
                }
                Err(e) => {
                    tracing::error!("Redis error during in-flight insert: {e}");
                    // On Redis error, rollback what we inserted and return infrastructure error
                    self.rollback_inflight_redis(&mut manager, &inserted_keys)
                        .await;
                    return Err(InflightInsertError::Infrastructure);
                }
            }
        }

        Ok(())
    }

    /// Rolls back previously inserted Redis keys during a failed atomic insertion.
    async fn rollback_inflight_redis(&self, manager: &mut ConnectionManager, keys: &[String]) {
        for key in keys {
            let result: Result<usize, redis::RedisError> = manager.del(key).await;
            if let Err(e) = result {
                tracing::error!("Failed to rollback Redis key {key}: {e}");
            }
        }
    }

    /// Removes in-flight addresses from Redis.
    async fn remove_inflight_redis(&self, mut manager: ConnectionManager, addresses: &[Address]) {
        for addr in addresses {
            let key = Self::inflight_key(addr);
            let result: Result<usize, redis::RedisError> = manager.del(&key).await;
            if let Err(e) = result {
                tracing::error!("Failed to remove in-flight key from Redis {key}: {e}");
            }
        }
    }

    /// Attempts to insert all addresses into the local cache using atomic compute operations.
    /// Returns `Err(Duplicate(addr))` if any address already exists, rolling back prior insertions.
    async fn try_insert_inflight_local(
        &self,
        addresses: &[Address],
    ) -> Result<(), InflightInsertError> {
        let mut inserted_addresses: Vec<Address> = Vec::new();

        for addr in addresses {
            let result = self
                .inflight_cache
                .entry_by_ref(addr)
                .and_compute_with(|entry| async move {
                    if entry.is_some() {
                        Op::Nop
                    } else {
                        Op::Put(())
                    }
                })
                .await;

            match result {
                CompResult::Inserted(_) => {
                    inserted_addresses.push(*addr);
                }
                CompResult::Unchanged(_) => {
                    // Already exists - rollback and return duplicate error
                    self.remove_inflight_local(&inserted_addresses).await;
                    return Err(InflightInsertError::Duplicate(*addr));
                }
                _ => unreachable!("Unexpected CompResult variant"),
            }
        }

        Ok(())
    }

    /// Removes in-flight addresses from the local cache.
    async fn remove_inflight_local(&self, addresses: &[Address]) {
        for addr in addresses {
            self.inflight_cache.invalidate(addr).await;
        }
    }
}

/// Converts a Redis error into a gateway error response.
fn handle_redis_error(e: redis::RedisError) -> GatewayErrorResponse {
    tracing::error!("Unhandled Redis error: {}", e);
    GatewayErrorResponse::internal_server_error()
}
