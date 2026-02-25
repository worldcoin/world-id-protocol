//! Redis-backed distributed nonce manager.
//!
//! Solves the "nonce too low" problem when multiple gateway replicas share
//! the same signer key by coordinating nonce allocation through Redis.
//!
//! # How it works
//!
//! Each signer address gets a Redis key (`gateway:nonce:{address}`) that holds
//! the last allocated nonce.  A Lua script atomically initialises from the
//! on-chain pending nonce (via `SETNX`) and then increments, guaranteeing
//! every caller – even across processes – receives a unique, monotonically
//! increasing nonce.
//!
//! # Failure modes
//!
//! * **Redis unavailable:** the manager returns a transport error and the
//!   batcher retries on the next batch cycle.
//! * **Redis flushed while running:** the init branch re-seeds from the
//!   on-chain pending count, so at worst one batch may collide with an
//!   already-pending transaction.  The RPC node will reject the duplicate and
//!   the batcher surfaces the error to callers.

use alloy::{
    network::Network,
    primitives::Address,
    providers::{fillers::NonceManager, Provider},
    transports::TransportResult,
};
use async_trait::async_trait;
use redis::aio::ConnectionManager;

/// Nonce key prefix in Redis – one key per signer address.
const NONCE_KEY_PREFIX: &str = "gateway:nonce";

/// A [`NonceManager`] that coordinates nonce allocation via Redis.
///
/// Safe for use across multiple replicas sharing the same signer key.
#[derive(Clone, Debug)]
pub struct RedisNonceManager {
    redis: ConnectionManager,
}

impl RedisNonceManager {
    /// Create a new `RedisNonceManager` from an existing Redis connection manager.
    pub fn new(redis: ConnectionManager) -> Self {
        Self { redis }
    }

    fn nonce_key(address: &Address) -> String {
        format!("{NONCE_KEY_PREFIX}:{address}")
    }
}

/// Lua script executed atomically in Redis.
///
/// 1. `SETNX key (on_chain_nonce - 1)` — initialises only on the very first
///    call (cold start / Redis flush).  The `-1` compensates for the `INCR`
///    that follows so the first returned nonce equals `on_chain_nonce`.
/// 2. `INCR key` — returns the next unique nonce.
/// 3. Safety floor: if the incremented value somehow falls below the on-chain
///    nonce (e.g. stale Redis data), we bump the key up and return the
///    on-chain value.
const NONCE_LUA: &str = r#"
local key = KEYS[1]
local on_chain = tonumber(ARGV[1])
-- Initialise only when the key does not exist yet
redis.call('SET', key, on_chain - 1, 'NX')
local next = redis.call('INCR', key)
-- Safety floor: never return a nonce below the on-chain pending count
if next < on_chain then
    redis.call('SET', key, on_chain)
    return on_chain
end
return next
"#;

#[async_trait]
impl NonceManager for RedisNonceManager {
    async fn get_next_nonce<P, N>(&self, provider: &P, address: Address) -> TransportResult<u64>
    where
        P: Provider<N>,
        N: Network,
    {
        // Fetch the on-chain pending nonce (includes mempool txs the node
        // knows about).  This is the floor for any nonce we hand out.
        let on_chain_nonce = provider.get_transaction_count(address).pending().await?;

        let key = Self::nonce_key(&address);
        let mut conn = self.redis.clone();

        let next: u64 = redis::Script::new(NONCE_LUA)
            .key(&key)
            .arg(on_chain_nonce)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %address, "Redis nonce allocation failed");
                alloy::transports::TransportErrorKind::custom_str(&format!(
                    "Redis nonce error: {e}"
                ))
            })?;

        tracing::debug!(
            %address,
            on_chain_nonce,
            allocated_nonce = next,
            "Allocated nonce via Redis"
        );

        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a Redis connection manager if `REDIS_URL` is set, otherwise
    /// skips the test.
    async fn redis_conn() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = redis::Client::open(url.as_str()).ok()?;
        ConnectionManager::new(client).await.ok()
    }

    /// Clean up test keys after each test.
    async fn cleanup(conn: &mut ConnectionManager, keys: &[&str]) {
        for key in keys {
            let _: Result<(), _> = redis::cmd("DEL").arg(key).query_async(conn).await;
        }
    }

    #[tokio::test]
    async fn test_nonce_lua_script_sequential() {
        let Some(mut conn) = redis_conn().await else {
            eprintln!("Skipping: Redis not available");
            return;
        };

        let key = "gateway:nonce:test_sequential";
        cleanup(&mut conn, &[key]).await;

        // Simulate on-chain nonce = 5
        let on_chain: u64 = 5;

        // First call should return 5
        let n1: u64 = redis::Script::new(NONCE_LUA)
            .key(key)
            .arg(on_chain)
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(n1, 5);

        // Second call should return 6
        let n2: u64 = redis::Script::new(NONCE_LUA)
            .key(key)
            .arg(on_chain)
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(n2, 6);

        // Third call should return 7
        let n3: u64 = redis::Script::new(NONCE_LUA)
            .key(key)
            .arg(on_chain)
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(n3, 7);

        cleanup(&mut conn, &[key]).await;
    }

    #[tokio::test]
    async fn test_nonce_lua_script_safety_floor() {
        let Some(mut conn) = redis_conn().await else {
            eprintln!("Skipping: Redis not available");
            return;
        };

        let key = "gateway:nonce:test_floor";
        cleanup(&mut conn, &[key]).await;

        // First: allocate nonce with on-chain = 3
        let n1: u64 = redis::Script::new(NONCE_LUA)
            .key(key)
            .arg(3u64)
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(n1, 3);

        // Now simulate the on-chain nonce jumping ahead to 10 (e.g. txs
        // confirmed). The safety floor should kick in.
        let n2: u64 = redis::Script::new(NONCE_LUA)
            .key(key)
            .arg(10u64)
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(n2, 10, "should jump to on-chain nonce when Redis value is stale");

        // Next allocation should be 11
        let n3: u64 = redis::Script::new(NONCE_LUA)
            .key(key)
            .arg(10u64)
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(n3, 11);

        cleanup(&mut conn, &[key]).await;
    }

    #[tokio::test]
    async fn test_nonce_lua_script_concurrent() {
        let Some(mut conn) = redis_conn().await else {
            eprintln!("Skipping: Redis not available");
            return;
        };

        let key = "gateway:nonce:test_concurrent";
        cleanup(&mut conn, &[key]).await;

        let on_chain: u64 = 0;
        let num_tasks: u64 = 50;

        let mut handles = Vec::new();
        for _ in 0..num_tasks {
            let mut c = conn.clone();
            handles.push(tokio::spawn(async move {
                let nonce: u64 = redis::Script::new(NONCE_LUA)
                    .key(key)
                    .arg(on_chain)
                    .invoke_async(&mut c)
                    .await
                    .unwrap();
                nonce
            }));
        }

        let mut nonces = Vec::new();
        for h in handles {
            nonces.push(h.await.unwrap());
        }

        nonces.sort();
        let expected: Vec<u64> = (0..num_tasks).collect();
        assert_eq!(nonces, expected, "all nonces must be unique and sequential");

        cleanup(&mut conn, &[key]).await;
    }
}
