//! Cleanup for requests that no owner is responsible for.
//!
//! Requests fall into two classes. Those referenced by a wallet record are owned
//! by the transaction resolver in [`crate::transaction_submitter`], which knows
//! their transaction and decides their fate. Everything else has no owner: a
//! request that never reached a batcher, a batcher that died holding a batch, or
//! a submission written by a gateway build that predates wallet records.
//!
//! This sweeper handles only the second class, plus the rare request whose
//! owning wallet record is gone. Receipt polling belongs to the transaction
//! resolver; duplicating it here would let two owners race to decide the same
//! request.

use std::time::Duration;

use alloy::primitives::Address;

use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};

use crate::{
    config::OrphanSweeperConfig,
    request_tracker::{RequestTracker, now_unix_secs},
    storage::{request_store::StatusGuard, wallet_store::WalletStore},
};

/// Runs the orphan sweeper loop indefinitely.
///
/// Sleeps for `config.interval_secs` between passes and never returns an error:
/// a failed pass is logged and the next one retries, because terminating the
/// task would silently disable cleanup.
pub async fn run_orphan_sweeper(
    tracker: RequestTracker,
    wallets: WalletStore,
    config: OrphanSweeperConfig,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(config.interval_secs)).await;
        sweep_once(&tracker, &wallets, &config).await;
    }
}

/// A single sweep pass.
///
/// Public so tests can call it directly without managing a background task.
pub async fn sweep_once(
    tracker: &RequestTracker,
    wallets: &WalletStore,
    config: &OrphanSweeperConfig,
) {
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
            // applies. The submitter re-checks the state before it broadcasts,
            // so a request failed here is never executed on chain.
            //
            // The guard is `Batching` alone: `Submitted` is deliberately excluded,
            // because the resolver may have adopted this request between the
            // snapshot and this write, and failing it then would contradict the
            // resolver's ownership.
            GatewayRequestState::Batching => {
                if age > config.stale_submitted_threshold_secs {
                    fail_unowned(
                        tracker,
                        id,
                        age,
                        StatusGuard::Batching,
                        "request stayed in batching past the threshold",
                    )
                    .await;
                }
            }
            GatewayRequestState::Queued => {
                if age > config.stale_queued_threshold_secs {
                    fail_unowned(
                        tracker,
                        id,
                        age,
                        StatusGuard::Queued,
                        "request timed out in queued state",
                    )
                    .await;
                }
            }
            // A submission is owned by the resolver while its wallet record
            // still lists it. Without a wallet (written by a build that predates
            // wallet records), or once that record is gone, nothing will ever
            // resolve it, so it is failed on the submitted threshold.
            GatewayRequestState::Submitted { .. } => {
                if age > config.stale_submitted_threshold_secs
                    && !wallet_owns(wallets, record.wallet, id).await
                {
                    fail_unowned(
                        tracker,
                        id,
                        age,
                        StatusGuard::Submitted,
                        "submission has no wallet record that can resolve it",
                    )
                    .await;
                }
            }
        }
    }
}

/// Whether a wallet record still lists `id` among the requests it resolves.
///
/// A Redis error counts as owned: the request is left for a later pass rather
/// than failed on no evidence.
async fn wallet_owns(wallets: &WalletStore, wallet: Option<Address>, id: &str) -> bool {
    let Some(wallet) = wallet else {
        return false;
    };
    match wallets.get(wallet).await {
        Ok(record) => record
            .as_ref()
            .and_then(|record| record.submission())
            .is_some_and(|submission| submission.request_ids.iter().any(|owned| owned == id)),
        Err(error) => {
            tracing::error!(%error, request_id = %id, %wallet, "sweeper: failed to read wallet record");
            true
        }
    }
}

/// Fails one unowned request using the guarded write.
///
/// `observed` is the state the sweep snapshot saw, which is what keeps the
/// sweeper from overwriting a status another owner has advanced since.
async fn fail_unowned(
    tracker: &RequestTracker,
    id: &str,
    age: u64,
    observed: StatusGuard,
    reason: &str,
) {
    tracing::warn!(request_id = %id, age_secs = age, "sweeper: failing stale request: {reason}");

    let status = GatewayRequestState::failed(reason, Some(GatewayErrorCode::InternalServerError));
    if let Err(error) = tracker.set_status_if(id, &[observed], status, None).await {
        tracing::error!(%error, request_id = %id, "sweeper: failed to fail a stale request");
    }
}
