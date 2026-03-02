//! Operations batcher for insert/remove/recover/update operations.
//!
//! This batcher collects operations and submits them via Multicall3.

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

struct OpsBatchHooks {
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
}

pub struct OpsBatcherRunner {
    loop_cfg: BatchLoopConfig<OpsEnvelope>,
    hooks: OpsBatchHooks,
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
        let loop_cfg = BatchLoopConfig::new(
            "ops",
            BacklogScope::Ops,
            max_batch_size,
            local_queue_limit,
            batch_policy,
            base_fee_cache,
            tracker,
            rx,
        );

        let hooks = OpsBatchHooks { registry };

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

impl OpsBatchHooks {
    async fn submit_ops_batch(&self, tracker: &RequestTracker, batch: Vec<OpsEnvelope>) {
        if batch.is_empty() {
            return;
        }

        let mc = Multicall3::new(MULTICALL3_ADDR, self.registry.provider().clone());

        let batch_size = batch.len();
        let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();

        ::metrics::counter!(METRICS_BATCH_SUBMITTED, "type" => "ops").increment(1);
        ::metrics::histogram!(METRICS_BATCH_SIZE, "type" => "ops").record(batch_size as f64);

        tracker
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
                tracker
                    .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                    .await;
            }
        }
    }
}

impl BatchLoopHooks for OpsBatchHooks {
    type Envelope = OpsEnvelope;

    async fn submit_batch(&self, tracker: &RequestTracker, batch: Vec<Self::Envelope>) {
        self.submit_ops_batch(tracker, batch).await;
    }

    async fn handle_no_backlog(
        &self,
        _tracker: &RequestTracker,
        queue: &mut VecDeque<TimedEnvelope<Self::Envelope>>,
    ) {
        let dropped = queue.len();
        tracing::warn!(
            dropped,
            "redis reports no queued backlog, dropping local ops queue entries to resync state"
        );
        queue.clear();
    }
}
