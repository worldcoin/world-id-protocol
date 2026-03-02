use std::{collections::VecDeque, sync::Arc};

use crate::{
    RequestTracker,
    batch_policy::BaseFeeCache,
    config::BatchPolicyConfig,
    error::parse_contract_error,
    metrics::{
        METRICS_BATCH_FAILURE, METRICS_BATCH_LATENCY_MS, METRICS_BATCH_SIZE,
        METRICS_BATCH_SUBMITTED, METRICS_BATCH_SUCCESS,
    },
    policy_batcher::{
        BatchLoopConfig, BatchLoopHooks, TimedEnvelope, run_legacy_loop, run_policy_loop,
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

struct CreateBatchHooks {
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
}

pub struct CreateBatcherRunner {
    loop_cfg: BatchLoopConfig<CreateReqEnvelope>,
    hooks: CreateBatchHooks,
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
        let loop_cfg = BatchLoopConfig::new(
            "create",
            BacklogScope::Create,
            max_batch_size,
            local_queue_limit,
            batch_policy,
            base_fee_cache,
            tracker,
            rx,
        );

        let hooks = CreateBatchHooks { registry };

        Self { loop_cfg, hooks }
    }

    pub async fn run(mut self) {
        if self.loop_cfg.batch_policy.enabled {
            run_policy_loop(&mut self.loop_cfg, &self.hooks).await;
        } else {
            run_legacy_loop(&mut self.loop_cfg, &self.hooks).await;
        }
    }
}

impl CreateBatchHooks {
    async fn drop_local_queue_and_inflight(
        &self,
        tracker: &RequestTracker,
        queue: &mut VecDeque<TimedEnvelope<CreateReqEnvelope>>,
    ) -> usize {
        let mut inflight_addresses = Vec::new();
        for timed in queue.drain(..) {
            inflight_addresses.extend(timed.envelope.req.authenticator_addresses);
        }

        let removed = inflight_addresses.len();
        if removed > 0 {
            tracker.remove_inflight(&inflight_addresses).await;
        }
        removed
    }

    async fn submit_create_batch(&self, tracker: &RequestTracker, batch: Vec<CreateReqEnvelope>) {
        if batch.is_empty() {
            return;
        }

        let batch_size = batch.len();
        let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();

        ::metrics::counter!(METRICS_BATCH_SUBMITTED, "type" => "create").increment(1);
        ::metrics::histogram!(METRICS_BATCH_SIZE, "type" => "create").record(batch_size as f64);

        tracker
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
                tracker
                    .set_status_batch(
                        &ids,
                        GatewayRequestState::Submitted {
                            tx_hash: hash.clone(),
                        },
                    )
                    .await;

                let tracker = tracker.clone();
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
                tracker
                    .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                    .await;
                // Remove all addresses from the in-flight tracker on send failure
                tracker.remove_inflight(&all_addresses).await;
            }
        }
    }
}

impl BatchLoopHooks for CreateBatchHooks {
    type Envelope = CreateReqEnvelope;

    async fn submit_batch(&self, tracker: &RequestTracker, batch: Vec<Self::Envelope>) {
        self.submit_create_batch(tracker, batch).await;
    }

    async fn handle_no_backlog(
        &self,
        tracker: &RequestTracker,
        queue: &mut VecDeque<TimedEnvelope<Self::Envelope>>,
    ) {
        let dropped = queue.len();
        let inflight_removed = self.drop_local_queue_and_inflight(tracker, queue).await;
        tracing::warn!(
            dropped,
            inflight_removed,
            "redis reports no queued backlog, dropping local create queue entries to resync state"
        );
    }
}
