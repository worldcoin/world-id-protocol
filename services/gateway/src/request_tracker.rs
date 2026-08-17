use std::time::{SystemTime, UNIX_EPOCH};
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestKind, GatewayRequestState};

pub use crate::storage::request_store::RequestRecord;
use crate::{
    batch_policy::BacklogUrgencyStats,
    config::RateLimitConfig,
    error::{GatewayErrorResponse, GatewayResult},
    metrics,
    storage::request_store::{CreateRequestOutcome, RateLimitOutcome, RequestStore},
};

/// Scope used to compute queued backlog stats for a specific batcher.
#[derive(Clone, Copy, Debug)]
pub enum BacklogScope {
    /// Include all request kinds.
    All,
    /// Include only create-account requests.
    Create,
    /// Include only ops requests (insert/update/remove/recover).
    Ops,
}

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
/// Uses shared persistent storage so tracking works across gateway replicas.
#[derive(Clone)]
pub struct RequestTracker {
    /// Persistent request storage.
    store: RequestStore,
    /// Rate limiting configuration, if enabled.
    rate_limit: Option<RateLimitConfig>,
}

impl RequestTracker {
    /// Initializes the request tracker instance.
    ///
    /// # Panics
    /// If the connection to Redis fails.
    pub async fn new(redis_url: String, rate_limit: Option<RateLimitConfig>) -> Self {
        Self {
            store: RequestStore::connect(&redis_url).await,
            rate_limit,
        }
    }

    /// Records a terminal request with a specific ID without adding it to the
    /// pending set or acquiring in-flight locks.
    ///
    /// This is intended for compatibility no-op endpoints that should be
    /// visible through `/status/{request_id}` even though there is no batcher or
    /// on-chain transaction to track.
    pub async fn new_terminal_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
        status: GatewayRequestState,
    ) -> Result<(), GatewayErrorResponse> {
        debug_assert!(
            matches!(
                &status,
                GatewayRequestState::Finalized { .. } | GatewayRequestState::Failed { .. }
            ),
            "new_terminal_request_with_id should only be used with terminal states"
        );

        self.store
            .create_terminal_request(&id, kind, status, now_unix_secs())
            .await
            .map_err(|error| {
                tracing::error!(%error, request_id = id, "Error creating terminal request");
                GatewayErrorResponse::internal_server_error()
            })
    }

    /// Creates a new request with a specific ID, atomically acquiring in-flight
    /// lock keys.
    ///
    /// If any in-flight key already exists, the operation is aborted and a
    /// `DuplicateRequestInFlight` error is returned.
    pub async fn new_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
        inflight_keys: Vec<String>,
    ) -> Result<(), GatewayErrorResponse> {
        match self
            .store
            .create_request(&id, kind, &inflight_keys, now_unix_secs())
            .await
        {
            Ok(CreateRequestOutcome::Created) => Ok(()),
            Ok(CreateRequestOutcome::DuplicateInflight(key)) => {
                tracing::info!(%key, "Duplicate in-flight request detected");
                metrics::increment_request_rejected("duplicate_inflight");
                Err(GatewayErrorResponse::bad_request(
                    GatewayErrorCode::DuplicateRequestInFlight,
                ))
            }
            Err(error) => {
                tracing::error!(%error, request_id = id, "Error creating request");
                Err(GatewayErrorResponse::internal_server_error())
            }
        }
    }

    /// Updates the status of multiple requests in a batch.
    pub async fn set_status_batch(&self, ids: &[String], status: GatewayRequestState) {
        for id in ids {
            if let Err(e) = self.update_stored_status(id, &status).await {
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

    /// Finalizes pending requests associated with a legacy transaction record.
    pub(crate) async fn finalize_submitted_transaction(
        &self,
        receipt_succeeded: bool,
        tx_hash: &str,
    ) {
        let ids = match self.get_pending_requests().await {
            Ok(ids) => ids,
            Err(error) => {
                tracing::error!(%error, %tx_hash, "failed to load requests for tracked transaction");
                return;
            }
        };
        let records = match self.snapshot_batch(&ids).await {
            Ok(records) => records,
            Err(error) => {
                tracing::error!(%error, %tx_hash, "failed to inspect requests for tracked transaction");
                return;
            }
        };
        let matching: Vec<String> = records
            .into_iter()
            .filter_map(|(id, record)| match record.map(|record| record.status) {
                Some(GatewayRequestState::Submitted {
                    tx_hash: request_hash,
                }) if request_hash == tx_hash => Some(id),
                _ => None,
            })
            .collect();
        self.finalize_from_receipt(&matching, receipt_succeeded, tx_hash)
            .await;
    }

    /// Returns a snapshot of the current state of a request, if it exists.
    pub async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        match self.store.request(id).await {
            Ok(record) => record,
            Err(error) => {
                tracing::error!(%error, request_id = id, "Failed to get request");
                None
            }
        }
    }

    /// Atomically updates a request's status and timestamp.
    async fn update_stored_status(
        &self,
        id: &str,
        status: &GatewayRequestState,
    ) -> GatewayResult<()> {
        self.store.update_status(id, status, now_unix_secs()).await
    }

    // =========================================================================
    // Pending-set helpers
    // =========================================================================

    /// Returns all request IDs currently in the pending set.
    pub async fn get_pending_requests(&self) -> GatewayResult<Vec<String>> {
        self.store.pending_request_ids().await
    }

    /// Fetches multiple request records in a single `MGET` round-trip.
    pub async fn snapshot_batch(
        &self,
        ids: &[String],
    ) -> GatewayResult<Vec<(String, Option<RequestRecord>)>> {
        self.store.requests(ids).await
    }

    /// Computes queued-backlog urgency statistics from pending requests.
    ///
    /// The stats are based only on requests currently in `Queued` state.
    pub async fn queued_backlog_stats(&self) -> GatewayResult<BacklogUrgencyStats> {
        self.queued_backlog_stats_for_scope(BacklogScope::All).await
    }

    /// Computes queued-backlog urgency statistics from pending requests in a given scope.
    ///
    /// The stats are based only on requests currently in `Queued` state and whose
    /// [`GatewayRequestKind`] belongs to `scope`.
    pub async fn queued_backlog_stats_for_scope(
        &self,
        scope: BacklogScope,
    ) -> GatewayResult<BacklogUrgencyStats> {
        let ids = self.get_pending_requests().await?;
        if ids.is_empty() {
            return Ok(BacklogUrgencyStats::default());
        }

        let records = self.snapshot_batch(&ids).await?;
        let now = now_unix_secs();
        let mut queued_count = 0usize;
        let mut oldest_age_secs = 0u64;
        for (_, maybe_record) in records {
            let Some(record) = maybe_record else {
                continue;
            };
            if !matches_scope(record.kind, scope) {
                continue;
            }
            if matches!(record.status, GatewayRequestState::Queued) {
                let age = now.saturating_sub(record.updated_at);
                queued_count += 1;
                oldest_age_secs = oldest_age_secs.max(age);
            }
        }

        if queued_count == 0 {
            return Ok(BacklogUrgencyStats::default());
        }

        Ok(BacklogUrgencyStats {
            queued_count,
            oldest_age_secs,
        })
    }

    /// Removes a request ID from the pending set (safety-net cleanup).
    pub async fn remove_from_pending_set(&self, id: &str) {
        if let Err(error) = self.store.remove_pending_request(id).await {
            tracing::error!(%error, request_id = id, "Failed to remove request from pending set");
        }
    }

    // =========================================================================
    // Rate limiting
    // =========================================================================

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
        let Some(ref rl) = self.rate_limit else {
            return Ok(());
        };
        let (window_secs, max_requests) = (rl.window_secs, rl.max_requests);

        let result = self
            .store
            .check_rate_limit(
                leaf_index,
                request_id,
                now_unix_secs(),
                window_secs,
                max_requests,
            )
            .await;

        match result {
            Ok(RateLimitOutcome::Exceeded) => {
                tracing::warn!(
                    leaf_index = leaf_index,
                    request_id = request_id,
                    "Rate limit exceeded"
                );
                metrics::increment_request_rejected("rate_limited");
                Err(GatewayErrorResponse::rate_limit_exceeded(
                    window_secs,
                    max_requests,
                ))
            }
            Ok(RateLimitOutcome::Allowed(count)) => {
                tracing::debug!(
                    leaf_index,
                    request_id,
                    count,
                    max = max_requests,
                    "Rate limit check passed"
                );
                Ok(())
            }
            Err(error) => {
                tracing::error!(%error, "Storage error during rate limit check");
                tracing::warn!("Rate limit check failed due to storage error, allowing request");
                Ok(())
            }
        }
    }
}

fn matches_scope(kind: GatewayRequestKind, scope: BacklogScope) -> bool {
    match scope {
        BacklogScope::All => true,
        BacklogScope::Create => matches!(kind, GatewayRequestKind::CreateAccount),
        BacklogScope::Ops => matches!(
            kind,
            GatewayRequestKind::InsertAuthenticator
                | GatewayRequestKind::UpdateAuthenticator
                | GatewayRequestKind::RemoveAuthenticator
                | GatewayRequestKind::UpdateRecoveryAgent
                | GatewayRequestKind::CancelRecoveryAgentUpdate
                | GatewayRequestKind::ExecuteRecoveryAgentUpdate
                | GatewayRequestKind::RecoverAccount
        ),
    }
}
