//! Request tracking with pluggable storage backend.

pub mod backend;
pub mod error;
pub mod state;

pub use backend::{DynStorage, StorageBackend, StoredRecord};
pub use state::Status;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use world_id_core::types::{GatewayErrorResponse, GatewayRequestKind, GatewayRequestState};

/// A tracked request record (API-facing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRecord {
    /// Request ID.
    pub id: Uuid,
    /// The kind of operation.
    pub kind: GatewayRequestKind,
    /// Current status.
    #[serde(default)]
    pub status: Status,
}

impl RequestRecord {
    /// Create a new record in Queued state.
    #[allow(dead_code)]
    pub fn new(id: Uuid, kind: GatewayRequestKind) -> Self {
        Self {
            id,
            kind,
            status: Status::Queued,
        }
    }

    /// Get the status as the API type.
    #[allow(dead_code)]
    pub fn api_status(&self) -> GatewayRequestState {
        (&self.status).into()
    }
}

impl From<StoredRecord> for RequestRecord {
    fn from(stored: StoredRecord) -> Self {
        Self {
            id: stored.id,
            kind: stored.kind,
            status: stored.status,
        }
    }
}

impl From<RequestRecord> for StoredRecord {
    fn from(record: RequestRecord) -> Self {
        Self {
            id: record.id,
            kind: record.kind,
            status: record.status,
        }
    }
}

/// Request tracker with pluggable storage.
#[derive(Clone)]
pub struct RequestTracker {
    storage: DynStorage,
}

impl RequestTracker {
    /// Initialize the request tracker.
    pub async fn new(redis_url: Option<String>) -> Self {
        let storage = DynStorage::new(redis_url).await;
        Self { storage }
    }

    /// Create a new request record.
    pub async fn create(
        &self,
        id: Uuid,
        kind: GatewayRequestKind,
    ) -> Result<RequestRecord, GatewayErrorResponse> {
        let record = StoredRecord::new(id, kind);
        self.storage.create(record.clone()).await.map_err(|e| {
            tracing::error!("Failed to create record: {e}");
            GatewayErrorResponse::internal_server_error()
        })?;
        Ok(record.into())
    }

    /// Get a request record by ID.
    pub async fn get(&self, id: Uuid) -> Option<RequestRecord> {
        match self.storage.get(id).await {
            Ok(Some(record)) => Some(record.into()),
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Failed to get record: {e}");
                None
            }
        }
    }

    /// Transition a request to a new status.
    pub async fn transition(&self, id: Uuid, to: Status) -> Result<(), GatewayErrorResponse> {
        self.storage.update_status(id, to).await.map_err(|e| {
            tracing::error!("Failed to transition record: {e}");
            GatewayErrorResponse::internal_server_error()
        })
    }

    /// Batch transition multiple requests to the same status.
    pub async fn transition_batch(&self, ids: &[Uuid], to: Status) {
        for &id in ids {
            if let Err(e) = self.transition(id, to.clone()).await {
                tracing::error!("Failed to transition {id}: {e:?}");
            }
        }
    }

    // === Legacy API compatibility ===

    /// Legacy: Create with string ID.
    #[allow(dead_code)]
    pub async fn new_request(
        &self,
        kind: GatewayRequestKind,
    ) -> Result<(String, RequestRecord), GatewayErrorResponse> {
        let id = Uuid::new_v4();
        let record = self.create(id, kind).await?;
        Ok((id.to_string(), record))
    }

    /// Legacy: Create with provided string ID.
    pub async fn new_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
    ) -> Result<(String, RequestRecord), GatewayErrorResponse> {
        let uuid = id.parse().unwrap_or_else(|_| Uuid::new_v4());
        let record = self.create(uuid, kind).await?;
        Ok((id, record))
    }

    /// Legacy: Set status with GatewayRequestState.
    pub async fn set_status(&self, id: &str, status: GatewayRequestState) {
        if let Ok(uuid) = id.parse() {
            let _ = self.transition(uuid, status.into()).await;
        }
    }

    /// Legacy: Batch set status.
    pub async fn set_status_batch(&self, ids: &[String], status: GatewayRequestState) {
        let uuids: Vec<Uuid> = ids.iter().filter_map(|s| s.parse().ok()).collect();
        self.transition_batch(&uuids, status.into()).await;
    }

    /// Legacy: Get snapshot by string ID.
    pub async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        let uuid = id.parse().ok()?;
        self.get(uuid).await
    }
}
