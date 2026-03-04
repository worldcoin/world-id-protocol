use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy::{
    primitives::TxHash,
    providers::{DynProvider, Provider},
};
use world_id_core::api_types::{GatewayErrorCode, GatewayRequestState};

use crate::{
    config::OrphanSweeperConfig,
    request_tracker::{RequestTracker, now_unix_secs},
};

/// Runs the orphan sweeper loop indefinitely.
///
/// Sleeps for `config.interval` between passes. Each pass calls [`sweep_once`]
/// to resolve orphaned requests that were left behind by crashed replicas.
pub async fn run_orphan_sweeper(
    tracker: RequestTracker,
    provider: Arc<DynProvider>,
    config: OrphanSweeperConfig,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(config.interval_secs)).await;
        sweep_once(&tracker, &provider, &config).await;
    }
}

/// A single sweep pass – public so that tests can call it directly without
/// managing background task lifecycle.
pub async fn sweep_once(
    tracker: &RequestTracker,
    provider: &DynProvider,
    config: &OrphanSweeperConfig,
) {
    let now = now_unix_secs();
    let pending_ids = match tracker.get_pending_requests().await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(error = %e, "sweeper: failed to fetch pending set, skipping pass");
            return;
        }
    };

    if pending_ids.is_empty() {
        return;
    }

    let records = match tracker.snapshot_batch(&pending_ids).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "sweeper: failed to snapshot pending records, skipping pass");
            return;
        }
    };

    // tx_hash -> [(request_id, updated_at)]
    let mut submitted_groups: HashMap<String, Vec<(String, u64)>> = HashMap::new();

    // Phase 1: check requests in the pending set
    for (id, maybe_record) in &records {
        // Pending set contains a request that has no status record in Redis. This likely never happens.
        let Some(record) = maybe_record else {
            tracker.remove_from_pending_set(id).await;
            continue;
        };

        match &record.status {
            // Requests that are finalized but were not removed from the pending set. This likely never happens.
            GatewayRequestState::Finalized { .. } | GatewayRequestState::Failed { .. } => {
                tracker.remove_from_pending_set(id).await;
            }
            GatewayRequestState::Queued | GatewayRequestState::Batching => {
                let age = now.saturating_sub(record.updated_at);
                if age > config.stale_queued_threshold_secs {
                    tracing::warn!(
                        request_id = %id,
                        age_secs = age,
                        "sweeper: failing stale {:?} request",
                        record.status,
                    );
                    tracker
                        .set_status(
                            id,
                            GatewayRequestState::failed(
                                "request orphaned (gateway replica lost before submission)",
                                Some(GatewayErrorCode::ConfirmationError),
                            ),
                        )
                        .await;
                }
            }
            GatewayRequestState::Submitted { tx_hash } => {
                submitted_groups
                    .entry(tx_hash.clone())
                    .or_default()
                    .push((id.clone(), record.updated_at));
            }
        }
    }

    // Phase 2: deduplicated receipt lookups for submitted requests
    for (tx_hash, group) in &submitted_groups {
        let Ok(hash) = tx_hash.parse::<TxHash>() else {
            // This should never happen unless there is some data corruption bug in Redis
            tracing::error!(tx_hash = %tx_hash, "sweeper: invalid tx_hash, failing group");
            // Fail requests since we can not look up the receipt anyways and the sweeper will run into the exact same error again and again until TTL is reached.
            for (id, _) in group {
                tracker
                    .set_status(
                        id,
                        GatewayRequestState::failed(
                            format!("corrupt tx_hash in request record: {tx_hash}"),
                            Some(GatewayErrorCode::ConfirmationError),
                        ),
                    )
                    .await;
            }
            continue;
        };

        match provider.get_transaction_receipt(hash).await {
            Ok(Some(receipt)) => {
                let ids: Vec<String> = group.iter().map(|(id, _)| id.clone()).collect();
                tracker
                    .finalize_from_receipt(&ids, receipt.status(), tx_hash)
                    .await;
            }
            Ok(None) => {
                for (id, updated_at) in group {
                    let age = now.saturating_sub(*updated_at);
                    // Request is stale if it has been submitted for longer than the threshold.
                    // We assume that sequencer has dropped the transaction from mempool if it hasn't been included in a block yet.
                    if age > config.stale_submitted_threshold_secs {
                        tracing::warn!(
                            request_id = %id,
                            tx_hash = %tx_hash,
                            age_secs = age,
                            "sweeper: failing stale submitted request (no receipt)",
                        );
                        tracker
                            .set_status(
                                id,
                                GatewayRequestState::failed(
                                    format!(
                                        "transaction not confirmed within timeout, likely dropped from mempool (tx: {tx_hash})"
                                    ),
                                    Some(GatewayErrorCode::ConfirmationError),
                                ),
                            )
                            .await;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    tx_hash = %tx_hash,
                    error = %e,
                    "sweeper: RPC error fetching receipt, skipping group",
                );
            }
        }
    }
}
