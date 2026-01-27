use std::time::Duration;

use alloy::primitives::Address;
use moka::{
    future::Cache,
    ops::compute::{CompResult, Op},
};
use redis::{aio::ConnectionManager, AsyncCommands, SetExpiry, SetOptions};

/// Default TTL for in-flight entries (5 minutes).
const INFLIGHT_TTL: Duration = Duration::from_secs(300);

/// Tracks in-flight authenticator addresses to prevent duplicate requests.
///
/// When Redis is configured, uses distributed locking via Redis SET NX.
/// Otherwise, falls back to local moka cache (single instance only).
#[derive(Clone)]
pub struct InflightTracker {
    /// Local cache for single-instance fallback.
    cache: Cache<Address, ()>,
    /// Optional Redis connection for distributed tracking.
    redis_manager: Option<ConnectionManager>,
}

impl InflightTracker {
    /// Creates a new in-flight tracker.
    ///
    /// If `redis_manager` is provided, uses Redis for distributed tracking.
    /// Otherwise, uses local moka cache only.
    pub fn new(redis_manager: Option<ConnectionManager>) -> Self {
        let cache = Cache::builder().time_to_live(INFLIGHT_TTL).build();

        Self {
            cache,
            redis_manager,
        }
    }

    /// Redis key for an authenticator address.
    fn redis_key(addr: &Address) -> String {
        format!("gateway:inflight:auth:{addr}")
    }

    /// Attempts to atomically insert all addresses as in-flight.
    ///
    /// Returns `Ok(())` if all addresses were successfully inserted.
    /// Returns `Err(addr)` if any address was already in-flight (returns the conflicting address).
    ///
    /// If insertion fails partway through, already-inserted addresses are rolled back.
    pub async fn try_insert_all(&self, addresses: &[Address]) -> Result<(), Address> {
        if let Some(manager) = &self.redis_manager {
            self.try_insert_all_redis(manager.clone(), addresses).await
        } else {
            self.try_insert_all_local(addresses).await
        }
    }

    /// Remove all addresses from the in-flight tracker.
    pub async fn remove_all(&self, addresses: &[Address]) {
        if let Some(manager) = &self.redis_manager {
            self.remove_all_redis(manager.clone(), addresses).await;
        } else {
            self.remove_all_local(addresses).await;
        }
    }

    // =========================================================================
    // Redis implementation
    // =========================================================================

    async fn try_insert_all_redis(
        &self,
        mut manager: ConnectionManager,
        addresses: &[Address],
    ) -> Result<(), Address> {
        let mut inserted_keys: Vec<String> = Vec::new();

        for addr in addresses {
            let key = Self::redis_key(addr);

            // SET NX with TTL - only sets if key doesn't exist
            let opts = SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(SetExpiry::EX(INFLIGHT_TTL.as_secs()));

            let result: Result<Option<()>, redis::RedisError> =
                manager.set_options(&key, "1", opts).await;

            match result {
                Ok(Some(())) => {
                    // Successfully inserted
                    inserted_keys.push(key);
                }
                Ok(None) => {
                    // Key already exists - rollback and return error
                    self.rollback_redis_keys(&mut manager, &inserted_keys).await;
                    return Err(*addr);
                }
                Err(e) => {
                    tracing::error!("Redis error during in-flight insert: {e}");
                    // On Redis error, rollback what we inserted and fall through
                    self.rollback_redis_keys(&mut manager, &inserted_keys).await;
                    return Err(*addr);
                }
            }
        }

        Ok(())
    }

    async fn rollback_redis_keys(&self, manager: &mut ConnectionManager, keys: &[String]) {
        for key in keys {
            if let Err(e) = manager.del::<_, ()>(key).await {
                tracing::error!("Failed to rollback Redis key {key}: {e}");
            }
        }
    }

    async fn remove_all_redis(&self, mut manager: ConnectionManager, addresses: &[Address]) {
        for addr in addresses {
            let key = Self::redis_key(addr);
            if let Err(e) = manager.del::<_, ()>(&key).await {
                tracing::error!("Failed to remove in-flight key from Redis {key}: {e}");
            }
        }
    }

    // =========================================================================
    // Local cache implementation (single instance fallback)
    // =========================================================================

    async fn try_insert_all_local(&self, addresses: &[Address]) -> Result<(), Address> {
        let mut inserted_addresses: Vec<Address> = Vec::new();

        for addr in addresses {
            let result = self
                .cache
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
                    // Already exists - rollback and return error
                    for inserted_addr in &inserted_addresses {
                        self.cache.invalidate(inserted_addr).await;
                    }
                    return Err(*addr);
                }
                _ => unreachable!("Unexpected CompResult variant"),
            }
        }

        Ok(())
    }

    async fn remove_all_local(&self, addresses: &[Address]) {
        for addr in addresses {
            self.cache.invalidate(addr).await;
        }
    }
}
