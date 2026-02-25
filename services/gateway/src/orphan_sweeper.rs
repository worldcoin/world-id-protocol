use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy::{
    primitives::B256,
    providers::{DynProvider, Provider},
};
use world_id_core::api_types::{GatewayErrorCode, GatewayRequestState};

use crate::request_tracker::{RequestTracker, now_unix_secs};

#[derive(Debug, Clone)]
pub struct OrphanSweeperConfig {
    pub interval: Duration,
    pub stale_queued_threshold: Duration,
    pub stale_submitted_threshold: Duration,
}

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
        tokio::time::sleep(config.interval).await;
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
    let pending_ids = tracker.get_pending_requests().await;

    if pending_ids.is_empty() {
        return;
    }

    let records = tracker.snapshot_batch(&pending_ids).await;

    // tx_hash -> [(request_id, updated_at)]
    let mut submitted_groups: HashMap<String, Vec<(String, u64)>> = HashMap::new();

    for (id, maybe_record) in &records {
        let Some(record) = maybe_record else {
            tracker.remove_from_pending_set(id).await;
            continue;
        };

        match &record.status {
            GatewayRequestState::Finalized { .. } | GatewayRequestState::Failed { .. } => {
                tracker.remove_from_pending_set(id).await;
            }
            GatewayRequestState::Queued | GatewayRequestState::Batching => {
                let age = now.saturating_sub(record.updated_at);
                if age > config.stale_queued_threshold.as_secs() {
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

    // Phase 2: deduplicated receipt lookups
    for (tx_hash, group) in &submitted_groups {
        let Ok(hash) = tx_hash.parse::<B256>() else {
            tracing::error!(tx_hash = %tx_hash, "sweeper: invalid tx_hash, skipping group");
            continue;
        };

        match provider.get_transaction_receipt(hash).await {
            Ok(Some(receipt)) => {
                let ids: Vec<String> = group.iter().map(|(id, _)| id.clone()).collect();
                if receipt.status() {
                    tracker
                        .set_status_batch(
                            &ids,
                            GatewayRequestState::Finalized {
                                tx_hash: tx_hash.clone(),
                            },
                        )
                        .await;
                } else {
                    tracker
                        .set_status_batch(
                            &ids,
                            GatewayRequestState::failed(
                                format!("transaction reverted on-chain (tx: {tx_hash})"),
                                Some(GatewayErrorCode::TransactionReverted),
                            ),
                        )
                        .await;
                }
            }
            Ok(None) => {
                for (id, updated_at) in group {
                    let age = now.saturating_sub(*updated_at);
                    if age > config.stale_submitted_threshold.as_secs() {
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
