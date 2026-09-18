//! Cleanup for requests that no owner is responsible for.
//!
//! Requests fall into two classes. Those referenced by a wallet record are owned
//! by the transaction resolver in [`crate::transaction_submitter`], which knows
//! their transaction and decides their fate. Everything else has no owner: a
//! request that never reached a batcher, a batcher that died holding a batch, or
//! a submission written by a gateway build that predates wallet records.
//!
//! This sweeper handles only the second class. It deliberately does not poll
//! receipts any more; doing so would duplicate the resolver's work and let two
//! owners race to decide the same request.

use std::time::Duration;

use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};

use crate::{
    config::OrphanSweeperConfig,
    request_tracker::{RequestTracker, now_unix_secs},
    storage::request_store::StatusGuard,
};

/// Runs the orphan sweeper loop indefinitely.
///
/// Sleeps for `config.interval_secs` between passes and never returns an error:
/// a failed pass is logged and the next one retries, because terminating the
/// task would silently disable cleanup.
pub async fn run_orphan_sweeper(tracker: RequestTracker, config: OrphanSweeperConfig) {
    loop {
        tokio::time::sleep(Duration::from_secs(config.interval_secs)).await;
        sweep_once(&tracker, &config).await;
    }
}

/// A single sweep pass.
///
/// Public so tests can call it directly without managing a background task.
pub async fn sweep_once(tracker: &RequestTracker, config: &OrphanSweeperConfig) {
    let now = now_unix_secs();
    let pending_ids = match tracker.get_pending_requests().await {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(%error, "sweeper: failed to fetch pending set, skipping pass");
            return;
        }
    };

    if pending_ids.is_empty() {
        return;
    }

    let records = match tracker.snapshot_batch(&pending_ids).await {
        Ok(records) => records,
        Err(error) => {
            tracing::error!(%error, "sweeper: failed to snapshot pending records, skipping pass");
            return;
        }
    };

    for (id, maybe_record) in &records {
        let Some(record) = maybe_record else {
            // The pending set contains an id with no record. The record's TTL
            // expired and nothing will remove it otherwise, so prune it here.
            tracker.remove_from_pending_set(id).await;
            continue;
        };

        let age = now.saturating_sub(record.updated_at);

        match &record.status {
            // Terminal but still in the pending set. This should not happen
            // because terminal transitions remove the id atomically, but pruning
            // is cheap and keeps the set bounded.
            GatewayRequestState::Finalized { .. } | GatewayRequestState::Failed { .. } => {
                tracker.remove_from_pending_set(id).await;
            }
            // `Batching` means a batcher took ownership. Requests it holds are
            // only abandoned if the owning process died, so the longer threshold
            // applies. The wallet resolver re-checks the state before it
            // broadcasts, so a request failed here is never executed on chain.
            GatewayRequestState::Batching => {
                if age > config.stale_submitted_threshold_secs {
                    fail_unowned(
                        tracker,
                        id,
                        age,
                        "request stayed in progress past the threshold",
                    )
                    .await;
                }
            }
            GatewayRequestState::Queued => {
                if age > config.stale_queued_threshold_secs {
                    fail_unowned(tracker, id, age, "request timed out in queued state").await;
                }
            }
            // A submission that knows which wallet signed it is owned by the
            // resolver, which has the transaction hash and the signed bytes and
            // can decide its fate properly.
            GatewayRequestState::Submitted { .. } if record.wallet.is_some() => {}
            // A submission with no wallet was written by a build that predates
            // wallet records. Nothing can resolve it, so it is failed on the
            // same threshold the previous sweeper used. This class disappears as
            // those records expire.
            GatewayRequestState::Submitted { .. } => {
                if age > config.stale_submitted_threshold_secs {
                    fail_unowned(
                        tracker,
                        id,
                        age,
                        "submission predates wallet leases and cannot be resolved",
                    )
                    .await;
                }
            }
        }
    }
}

/// Fails one unowned request using the guarded write.
///
/// The guard means the sweeper can never overwrite a status another owner has
/// already advanced, which is what keeps it from reporting a request as failed
/// while its transaction is on chain.
async fn fail_unowned(tracker: &RequestTracker, id: &str, age: u64, reason: &str) {
    tracing::warn!(request_id = %id, age_secs = age, "sweeper: failing stale request: {reason}");

    let status = GatewayRequestState::failed(reason, Some(GatewayErrorCode::InternalServerError));
    let allowed = [StatusGuard::Queued, StatusGuard::Batching];
    if let Err(error) = tracker.set_status_if(id, &allowed, status, None).await {
        tracing::error!(%error, request_id = %id, "sweeper: failed to fail a stale request");
    }
}
