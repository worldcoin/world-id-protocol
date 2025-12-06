use std::{collections::HashMap, sync::Arc, time::Duration};

use redis::{aio::ConnectionManager, AsyncTypedCommands, Client, SetExpiry, SetOptions};
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::Instant};
use utoipa::ToSchema;

use crate::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    CreateAccount,
    UpdateAuthenticator,
    InsertAuthenticator,
    RemoveAuthenticator,
    RecoverAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RequestState {
    Queued,
    Batching,
    Submitted { tx_hash: String },
    Finalized { tx_hash: String },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRecord {
    pub kind: RequestKind,
    pub status: RequestState,
}

struct InMemoryRecord {
    record: RequestRecord,
    created_at: Instant,
}

const REQUESTS_TTL: u64 = 86_400; // 24 hours
const MEMORY_CLEANUP_INTERVAL: Duration = Duration::from_secs(3_600);

/// Global request tracker instance.
///
/// Tracks all requests made to the gateway by ID for async querying.
///
/// Using Redis is strongly recommended for production environments, and especially multi-node setups.
#[derive(Clone)]
pub struct RequestTracker {
    inner: Arc<RwLock<HashMap<String, InMemoryRecord>>>,
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

            Some(manager)
        } else {
            tracing::info!("No Redis URL provided, using in-memory request storage");
            None
        };

        let tracker = Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            redis_manager,
        };

        // Spawn background cleanup task for in-memory storage
        if tracker.redis_manager.is_none() {
            let inner = tracker.inner.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(MEMORY_CLEANUP_INTERVAL).await;
                    let mut map = inner.write().await;
                    let now = Instant::now();
                    map.retain(|_, record| {
                        now.duration_since(record.created_at) < Duration::from_secs(REQUESTS_TTL)
                    });
                    tracing::info!(
                        "Cleaned up expired in-memory request records. Current count: {}",
                        map.len()
                    );
                }
            });
        }

        tracker
    }

    fn request_key(id: &str) -> String {
        format!("gateway:request:{}", id)
    }

    pub async fn new_request(
        &self,
        kind: RequestKind,
    ) -> Result<(String, RequestRecord), ApiError> {
        let id = uuid::Uuid::new_v4().to_string();
        let record = RequestRecord {
            kind,
            status: RequestState::Queued,
        };

        if let Some(mut manager) = self.redis_manager.clone() {
            let key = Self::request_key(&id);
            let json_str = serde_json::to_string(&record).map_err(|e| {
                tracing::error!("FATAL: unable to serialize a RequestRecord: {e}");
                ApiError::internal_server_error()
            })?;

            let opts = SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(SetExpiry::EX(REQUESTS_TTL));

            manager
                .set_options(&key, json_str, opts)
                .await
                .map_err(handle_redis_error)?;
        } else {
            // Use in-memory storage
            self.inner.write().await.insert(
                id.clone(),
                InMemoryRecord {
                    record: record.clone(),
                    created_at: Instant::now(),
                },
            );
        }

        Ok((id, record))
    }

    pub async fn set_status_batch(&self, ids: &[String], status: RequestState) {
        if self.redis_manager.is_some() {
            for id in ids {
                if let Err(e) = self.set_status_on_redis(id, &status).await {
                    tracing::error!("Error updating status for request: {e}");
                }
            }
        } else {
            // Update in-memory
            let mut map = self.inner.write().await;
            for id in ids {
                if let Some(mem_rec) = map.get_mut(id) {
                    mem_rec.record.status = status.clone();
                }
            }
        }
    }

    pub async fn set_status(&self, id: &str, status: RequestState) {
        self.set_status_batch(&[id.to_string()], status).await;
    }

    pub async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        if let Some(mut manager) = self.redis_manager.clone() {
            // Try to get from Redis
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
            // Get from in-memory storage
            self.inner.read().await.get(id).map(|r| r.record.clone())
        }
    }

    /// Sets the status of a specific request in Redis.
    async fn set_status_on_redis(&self, id: &str, status: &RequestState) -> anyhow::Result<()> {
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

                local ttl = redis.call('TTL', KEYS[1])
                if ttl > 0 then
                    redis.call('SET', KEYS[1], updated, 'EX', ttl)
                else
                    redis.call('SET', KEYS[1], updated)
                end

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
}

fn handle_redis_error(e: redis::RedisError) -> ApiError {
    tracing::error!("Unhandled Redis error: {}", e);
    ApiError::internal_server_error()
}
