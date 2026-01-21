//! Pluggable storage backends for request tracking.

use super::{error::StorageError, state::Status};
use moka::future::Cache;
use redis::{aio::ConnectionManager, Client};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;
use world_id_core::types::GatewayRequestKind;

const REQUESTS_TTL: u64 = 86_400; // 24 hours
const CACHE_MAX_CAPACITY: u64 = 100_000;

/// A stored request record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    pub id: Uuid,
    pub kind: GatewayRequestKind,
    pub status: Status,
}

impl StoredRecord {
    pub fn new(id: Uuid, kind: GatewayRequestKind) -> Self {
        Self {
            id,
            kind,
            status: Status::Queued,
        }
    }
}

/// Storage backend trait for request persistence.
pub trait StorageBackend: Send + Sync + Clone + 'static {
    /// Store a new record. Returns error if record already exists.
    fn create(
        &self,
        record: StoredRecord,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;

    /// Get a record by ID.
    fn get(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<StoredRecord>, StorageError>> + Send;

    /// Update the status of a record. Returns error if not found.
    fn update_status(
        &self,
        id: Uuid,
        status: Status,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;
}

/// In-memory storage backend using moka cache with TTL.
#[derive(Clone)]
pub struct InMemoryBackend {
    cache: Cache<Uuid, StoredRecord>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        let cache = Cache::builder()
            .max_capacity(CACHE_MAX_CAPACITY)
            .time_to_live(Duration::from_secs(REQUESTS_TTL))
            .build();
        Self { cache }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    async fn create(&self, record: StoredRecord) -> Result<(), StorageError> {
        self.cache.insert(record.id, record).await;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<StoredRecord>, StorageError> {
        Ok(self.cache.get(&id).await)
    }

    async fn update_status(&self, id: Uuid, status: Status) -> Result<(), StorageError> {
        match self.cache.get(&id).await {
            Some(mut record) => {
                let current = &record.status;
                if !current.can_transition_to(&status) {
                    return Err(StorageError::InvalidTransition {
                        id,
                        from: current.clone(),
                        to: status,
                    });
                }
                record.status = status;
                self.cache.insert(id, record).await;
                Ok(())
            }
            None => Err(StorageError::NotFound(id)),
        }
    }
}

/// Redis storage backend for production.
#[derive(Clone)]
pub struct RedisBackend {
    conn: ConnectionManager,
}

impl RedisBackend {
    pub async fn new(url: &str) -> Result<Self, StorageError> {
        let client = Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        tracing::info!("Redis connection established");
        Ok(Self { conn })
    }

    fn key(id: Uuid) -> String {
        format!("gateway:req:{id}")
    }
}

impl StorageBackend for RedisBackend {
    async fn create(&self, record: StoredRecord) -> Result<(), StorageError> {
        let mut conn = self.conn.clone();
        let key = Self::key(record.id);
        let json = serde_json::to_string(&record)?;

        redis::cmd("SET")
            .arg(&key)
            .arg(&json)
            .arg("EX")
            .arg(REQUESTS_TTL)
            .arg("NX")
            .query_async::<()>(&mut conn)
            .await?;

        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<StoredRecord>, StorageError> {
        let mut conn = self.conn.clone();
        let key = Self::key(id);

        let result: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;

        match result {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn update_status(&self, id: Uuid, status: Status) -> Result<(), StorageError> {
        match self.get(id).await? {
            Some(record) => match record.status.can_transition_to(&status) {
                true => record.status,
                false => {
                    return Err(StorageError::InvalidTransition {
                        id,
                        from: record.status,
                        to: status,
                    })
                }
            },
            None => return Err(StorageError::NotFound(id)),
        };
        let mut conn = self.conn.clone();
        let key = Self::key(id);
        let status_json = serde_json::to_string(&status)?;

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
            .invoke_async(&mut conn)
            .await;

        result?;
        Ok(())
    }
}

/// Dynamic storage that can be either Redis or InMemory.
#[derive(Clone)]
pub enum DynStorage {
    Redis(RedisBackend),
    InMemory(InMemoryBackend),
}

impl DynStorage {
    pub async fn new(redis_url: Option<String>) -> Self {
        match redis_url {
            Some(url) => match RedisBackend::new(&url).await {
                Ok(backend) => Self::Redis(backend),
                Err(e) => {
                    tracing::error!("Failed to connect to Redis: {e}, falling back to in-memory");
                    Self::InMemory(InMemoryBackend::new())
                }
            },
            None => {
                tracing::info!("No Redis URL provided, using in-memory storage");
                Self::InMemory(InMemoryBackend::new())
            }
        }
    }
}

impl StorageBackend for DynStorage {
    async fn create(&self, record: StoredRecord) -> Result<(), StorageError> {
        match self {
            Self::Redis(b) => b.create(record).await,
            Self::InMemory(b) => b.create(record).await,
        }
    }

    async fn get(&self, id: Uuid) -> Result<Option<StoredRecord>, StorageError> {
        match self {
            Self::Redis(b) => b.get(id).await,
            Self::InMemory(b) => b.get(id).await,
        }
    }

    async fn update_status(&self, id: Uuid, status: Status) -> Result<(), StorageError> {
        match self {
            Self::Redis(b) => b.update_status(id, status).await,
            Self::InMemory(b) => b.update_status(id, status).await,
        }
    }
}
