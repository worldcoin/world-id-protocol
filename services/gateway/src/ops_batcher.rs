//! Operations batcher for insert/remove/recover/update operations.
//!
//! This batcher collects operations and submits them via Multicall3.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use crate::{
    RequestTracker,
    batch_policy::{
        BacklogUrgencyStats, BaseFeeCache, BatchPolicyEngine, DecisionReason, record_policy_metrics,
    },
    config::BatchPolicyConfig,
    error::parse_contract_error,
    metrics::{
        METRICS_BATCH_FAILURE, METRICS_BATCH_LATENCY_MS, METRICS_BATCH_SIZE,
        METRICS_BATCH_SUBMITTED, METRICS_BATCH_SUCCESS,
    },
    request_tracker::BacklogScope,
};
use alloy::{
    primitives::{Address, Bytes, address},
    providers::DynProvider,
};
use tokio::{sync::mpsc, time::Instant};
use world_id_core::{
    api_types::{GatewayErrorCode, GatewayRequestState},
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

const MULTICALL3_ADDR: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) payable returns (Result[] memory returnData);
    }
}

#[derive(Clone)]
pub struct OpsBatcherHandle {
    pub tx: mpsc::Sender<OpsEnvelope>,
}

/// Envelope for ops batcher containing pre-computed calldata.
#[derive(Debug)]
pub struct OpsEnvelope {
    pub id: String,
    pub calldata: Bytes,
}

struct TimedOpsEnvelope {
    enqueued_at: Instant,
    envelope: OpsEnvelope,
}

pub struct OpsBatcherRunner {
    rx: mpsc::Receiver<OpsEnvelope>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    max_batch_size: usize,
    local_queue_limit: usize,
    tracker: RequestTracker,
    batch_policy: BatchPolicyConfig,
    base_fee_cache: BaseFeeCache,
}

impl OpsBatcherRunner {
    pub fn new(
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        max_batch_size: usize,
        local_queue_limit: usize,
        rx: mpsc::Receiver<OpsEnvelope>,
        tracker: RequestTracker,
        batch_policy: BatchPolicyConfig,
        base_fee_cache: BaseFeeCache,
    ) -> Self {
        Self {
            rx,
            registry,
            max_batch_size,
            local_queue_limit: local_queue_limit.max(1),
            tracker,
            batch_policy,
            base_fee_cache,
        }
    }

    pub async fn run(mut self) {
        if self.batch_policy.enabled {
            self.run_policy().await;
        } else {
            self.run_legacy().await;
        }
    }

    async fn run_legacy(&mut self) {
        let window = Duration::from_millis(self.batch_policy.reeval_ms);
        loop {
            let Some(first) = self.rx.recv().await else {
                tracing::info!("ops batcher channel closed");
                return;
            };

            let mut batch = vec![first];
            let deadline = Instant::now() + window;

            loop {
                if batch.len() >= self.max_batch_size {
                    break;
                }
                match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                    Ok(Some(req)) => batch.push(req),
                    Ok(None) => {
                        tracing::info!("ops batcher channel closed while batching");
                        break;
                    }
                    Err(_) => break, // Timeout expired
                }
            }

            self.submit_batch(batch).await;
        }
    }

    async fn run_policy(&mut self) {
        let mut policy_engine = BatchPolicyEngine::new(self.batch_policy.clone());
        let reeval_interval = Duration::from_millis(self.batch_policy.reeval_ms);

        let mut queue: VecDeque<TimedOpsEnvelope> = VecDeque::new();
        let mut next_eval = Instant::now() + reeval_interval;
        let mut rx_open = true;
        let mut queue_backpressure_logged = false;

        while rx_open || !queue.is_empty() {
            if queue.len() >= self.local_queue_limit {
                if !queue_backpressure_logged {
                    tracing::warn!(
                        queue_len = queue.len(),
                        local_queue_limit = self.local_queue_limit,
                        "ops policy queue reached local capacity, pausing intake for backpressure"
                    );
                    queue_backpressure_logged = true;
                }
            } else {
                queue_backpressure_logged = false;
            }

            if queue.is_empty() {
                if !rx_open {
                    break;
                }
                match self.rx.recv().await {
                    Some(first) => {
                        queue.push_back(TimedOpsEnvelope {
                            enqueued_at: Instant::now(),
                            envelope: first,
                        });
                        next_eval = Instant::now() + reeval_interval;
                    }
                    None => {
                        tracing::info!("ops batcher channel closed");
                        rx_open = false;
                    }
                }
                continue;
            }

            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(next_eval) => {
                    let cost_score = policy_engine.update_cost_score(self.base_fee_cache.latest());

                    let fallback_age = queue
                        .front()
                        .map(|first| Instant::now().duration_since(first.enqueued_at).as_secs())
                        .unwrap_or_default();

                    let stats = match self
                        .tracker
                        .queued_backlog_stats_for_scope(BacklogScope::Ops)
                        .await
                    {
                        Ok(stats) => stats,
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to read queued backlog stats; using local fallback");
                            BacklogUrgencyStats {
                                queued_count: queue.len(),
                                oldest_age_secs: fallback_age,
                            }
                        }
                    };

                    let decision = policy_engine.evaluate(stats, self.max_batch_size, cost_score);
                    record_policy_metrics("ops", &decision);

                    if !decision.should_send {
                        if matches!(decision.reason, DecisionReason::NoBacklog) && !queue.is_empty()
                        {
                            let dropped = queue.len();
                            tracing::warn!(
                                dropped,
                                "redis reports no queued backlog, dropping local ops queue entries to resync state"
                            );
                            queue.clear();
                        }
                        next_eval = Instant::now() + reeval_interval;
                        continue;
                    }

                    let take_n = decision.target_batch_size.min(queue.len()).max(1);
                    let batch: Vec<OpsEnvelope> = queue
                        .drain(..take_n)
                        .map(|timed| timed.envelope)
                        .collect();
                    self.submit_batch(batch).await;

                    next_eval = Instant::now() + reeval_interval;
                }
                maybe_req = self.rx.recv(), if rx_open && queue.len() < self.local_queue_limit => {
                    match maybe_req {
                        Some(req) => {
                            queue.push_back(TimedOpsEnvelope {
                                enqueued_at: Instant::now(),
                                envelope: req,
                            });
                        }
                        None => {
                            tracing::info!("ops batcher channel closed while policy batching");
                            rx_open = false;
                        }
                    }
                }
            }
        }
    }

    async fn submit_batch(&self, batch: Vec<OpsEnvelope>) {
        if batch.is_empty() {
            return;
        }

        let mc = Multicall3::new(MULTICALL3_ADDR, self.registry.provider().clone());

        let batch_size = batch.len();
        let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();

        ::metrics::counter!(METRICS_BATCH_SUBMITTED, "type" => "ops").increment(1);
        ::metrics::histogram!(METRICS_BATCH_SIZE, "type" => "ops").record(batch_size as f64);

        self.tracker
            .set_status_batch(&ids, GatewayRequestState::Batching)
            .await;

        let calls: Vec<Multicall3::Call3> = batch
            .into_iter()
            .map(|env| Multicall3::Call3 {
                target: *self.registry.address(),
                allowFailure: false,
                callData: env.calldata,
            })
            .collect();

        let start = Instant::now();
        let res = mc.aggregate3(calls).send().await;
        match res {
            Ok(builder) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "ops").record(latency_ms);
                ::metrics::counter!(METRICS_BATCH_SUCCESS, "type" => "ops").increment(1);

                let hash = format!("0x{:x}", builder.tx_hash());
                self.tracker
                    .set_status_batch(
                        &ids,
                        GatewayRequestState::Submitted {
                            tx_hash: hash.clone(),
                        },
                    )
                    .await;

                let tracker = self.tracker.clone();
                let ids_for_receipt = ids;
                tokio::spawn(async move {
                    match builder.get_receipt().await {
                        Ok(receipt) => {
                            tracker
                                .finalize_from_receipt(&ids_for_receipt, receipt.status(), &hash)
                                .await;
                        }
                        Err(err) => {
                            tracker
                                .set_status_batch(
                                    &ids_for_receipt,
                                    GatewayRequestState::failed(
                                        format!("transaction confirmation error: {err}"),
                                        Some(GatewayErrorCode::ConfirmationError),
                                    ),
                                )
                                .await;
                        }
                    }
                });
            }
            Err(e) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "ops").record(latency_ms);
                ::metrics::counter!(METRICS_BATCH_FAILURE, "type" => "ops").increment(1);

                tracing::warn!(error = %e, "multicall3 send failed");
                let error_str = e.to_string();
                let code = parse_contract_error(&error_str);
                self.tracker
                    .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                    .await;
            }
        }
    }
}
