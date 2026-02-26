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
    primitives::{Address, U256},
    providers::DynProvider,
};
use tokio::{sync::mpsc, time::Instant};
use world_id_core::{
    api_types::{CreateAccountRequest, GatewayErrorCode, GatewayRequestState},
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

#[derive(Clone)]
pub struct CreateBatcherHandle {
    pub tx: mpsc::Sender<CreateReqEnvelope>,
}

#[derive(Debug)]
pub struct CreateReqEnvelope {
    pub id: String,
    pub req: CreateAccountRequest,
}

struct TimedCreateReqEnvelope {
    enqueued_at: Instant,
    envelope: CreateReqEnvelope,
}

pub struct CreateBatcherRunner {
    rx: mpsc::Receiver<CreateReqEnvelope>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    max_batch_size: usize,
    local_queue_limit: usize,
    tracker: RequestTracker,
    batch_policy: BatchPolicyConfig,
    base_fee_cache: BaseFeeCache,
}

impl CreateBatcherRunner {
    pub fn new(
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        max_batch_size: usize,
        local_queue_limit: usize,
        rx: mpsc::Receiver<CreateReqEnvelope>,
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
                tracing::info!("create batcher channel closed");
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
                        tracing::info!("create batcher channel closed while batching");
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

        let mut queue: VecDeque<TimedCreateReqEnvelope> = VecDeque::new();
        let mut next_eval = Instant::now() + reeval_interval;
        let mut rx_open = true;
        let mut queue_backpressure_logged = false;

        while rx_open || !queue.is_empty() {
            if queue.len() >= self.local_queue_limit {
                if !queue_backpressure_logged {
                    tracing::warn!(
                        queue_len = queue.len(),
                        local_queue_limit = self.local_queue_limit,
                        "create policy queue reached local capacity, pausing intake for backpressure"
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
                        queue.push_back(TimedCreateReqEnvelope {
                            enqueued_at: Instant::now(),
                            envelope: first,
                        });
                        next_eval = Instant::now() + reeval_interval;
                    }
                    None => {
                        tracing::info!("create batcher channel closed");
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
                        .queued_backlog_stats_for_scope(BacklogScope::Create)
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
                    record_policy_metrics("create", &decision);

                    if !decision.should_send {
                        if matches!(decision.reason, DecisionReason::NoBacklog) && !queue.is_empty()
                        {
                            let dropped = queue.len();
                            let inflight_removed =
                                self.drop_local_queue_and_inflight(&mut queue).await;
                            tracing::warn!(
                                dropped,
                                inflight_removed,
                                "redis reports no queued backlog, dropping local create queue entries to resync state"
                            );
                        }
                        next_eval = Instant::now() + reeval_interval;
                        continue;
                    }

                    let take_n = decision.target_batch_size.min(queue.len()).max(1);
                    let batch: Vec<CreateReqEnvelope> = queue
                        .drain(..take_n)
                        .map(|timed| timed.envelope)
                        .collect();
                    self.submit_batch(batch).await;

                    next_eval = Instant::now() + reeval_interval;
                }
                maybe_req = self.rx.recv(), if rx_open && queue.len() < self.local_queue_limit => {
                    match maybe_req {
                        Some(req) => {
                            queue.push_back(TimedCreateReqEnvelope {
                                enqueued_at: Instant::now(),
                                envelope: req,
                            });
                        }
                        None => {
                            tracing::info!("create batcher channel closed while policy batching");
                            rx_open = false;
                        }
                    }
                }
            }
        }
    }

    async fn drop_local_queue_and_inflight(
        &self,
        queue: &mut VecDeque<TimedCreateReqEnvelope>,
    ) -> usize {
        let mut inflight_addresses = Vec::new();
        for timed in queue.drain(..) {
            inflight_addresses.extend(timed.envelope.req.authenticator_addresses);
        }

        let removed = inflight_addresses.len();
        if removed > 0 {
            self.tracker.remove_inflight(&inflight_addresses).await;
        }
        removed
    }

    async fn submit_batch(&self, batch: Vec<CreateReqEnvelope>) {
        if batch.is_empty() {
            return;
        }

        let batch_size = batch.len();
        let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();

        ::metrics::counter!(METRICS_BATCH_SUBMITTED, "type" => "create").increment(1);
        ::metrics::histogram!(METRICS_BATCH_SIZE, "type" => "create").record(batch_size as f64);

        self.tracker
            .set_status_batch(&ids, GatewayRequestState::Batching)
            .await;

        let mut recovery_addresses: Vec<Address> = Vec::new();
        let mut auths: Vec<Vec<Address>> = Vec::new();
        let mut pubkeys: Vec<Vec<U256>> = Vec::new();
        let mut commits: Vec<U256> = Vec::new();

        // Collect all authenticator addresses from this batch for cache cleanup
        let mut all_addresses: Vec<Address> = Vec::new();
        for env in batch {
            all_addresses.extend(env.req.authenticator_addresses.iter());
            recovery_addresses.push(env.req.recovery_address.unwrap_or(Address::ZERO));
            auths.push(env.req.authenticator_addresses);
            pubkeys.push(env.req.authenticator_pubkeys);
            commits.push(env.req.offchain_signer_commitment);
        }

        let call = self
            .registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits);

        let start = Instant::now();
        match call.send().await {
            Ok(builder) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "create")
                    .record(latency_ms);
                ::metrics::counter!(METRICS_BATCH_SUCCESS, "type" => "create").increment(1);

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
                let addresses_for_cleanup = all_addresses;
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
                    // Remove all addresses from the in-flight tracker after finalization
                    tracker.remove_inflight(&addresses_for_cleanup).await;
                });
            }
            Err(err) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "create")
                    .record(latency_ms);
                ::metrics::counter!(METRICS_BATCH_FAILURE, "type" => "create").increment(1);

                tracing::error!(error = %err, "create batch send failed");
                let error_str = err.to_string();
                let code = parse_contract_error(&error_str);
                self.tracker
                    .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                    .await;
                // Remove all addresses from the in-flight tracker on send failure
                self.tracker.remove_inflight(&all_addresses).await;
            }
        }
    }
}
