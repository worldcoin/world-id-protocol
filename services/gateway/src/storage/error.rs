//! Error types for the request tracker.

use super::state::Status;
use uuid::Uuid;

/// Errors from the storage backend.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("request not found: {0}")]
    NotFound(Uuid),

    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid transition for {id}: {from:?} -> {to:?}")]
    InvalidTransition { id: Uuid, from: Status, to: Status },
}
