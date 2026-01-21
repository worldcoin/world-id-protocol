//! Error types for the request tracker.

use super::state::Status;
use uuid::Uuid;
use world_id_core::types::GatewayErrorResponse;

/// Errors that can occur during request tracking.
#[derive(Debug, thiserror::Error)]
pub enum TrackerError {
    #[error("request not found: {0}")]
    NotFound(Uuid),

    #[error("invalid transition for {id}: {from:?} -> {to:?}")]
    InvalidTransition { id: Uuid, from: Status, to: Status },

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

impl From<TrackerError> for GatewayErrorResponse {
    fn from(err: TrackerError) -> Self {
        match err {
            TrackerError::NotFound(_) => GatewayErrorResponse::not_found(),
            TrackerError::InvalidTransition { .. } => GatewayErrorResponse::internal_server_error(),
            TrackerError::Storage(_) => GatewayErrorResponse::internal_server_error(),
        }
    }
}

/// Errors from the storage backend.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("request not found: {0}")]
    NotFound(Uuid),

    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("connection pool error")]
    Pool,
}
