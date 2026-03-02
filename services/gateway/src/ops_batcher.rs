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
    policy_batcher::{PolicyBatchLoopRunner, TimedEnvelope},
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
            self.run_policy_loop().await;
        } else {
            self.run_legacy_loop().await;
        }
    }

    async fn submit_ops_batch(&self, batch: Vec<OpsEnvelope>) {
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

impl PolicyBatchLoopRunner for OpsBatcherRunner {
    type Envelope = OpsEnvelope;

    fn batch_type(&self) -> &'static str {
        "ops"
    }

    fn backlog_scope(&self) -> BacklogScope {
        BacklogScope::Ops
    }

    fn max_batch_size(&self) -> usize {
        self.max_batch_size
    }

    fn local_queue_limit(&self) -> usize {
        self.local_queue_limit
    }

    fn batch_policy(&self) -> &BatchPolicyConfig {
        &self.batch_policy
    }

    fn base_fee_cache(&self) -> &BaseFeeCache {
        &self.base_fee_cache
    }

    fn tracker(&self) -> &RequestTracker {
        &self.tracker
    }

    fn rx(&mut self) -> &mut mpsc::Receiver<Self::Envelope> {
        &mut self.rx
    }

    async fn submit_batch(&self, batch: Vec<Self::Envelope>) {
        self.submit_ops_batch(batch).await;
    }

    async fn handle_no_backlog(&self, queue: &mut VecDeque<TimedEnvelope<Self::Envelope>>) {
        let dropped = queue.len();
        tracing::warn!(
            dropped,
            "redis reports no queued backlog, dropping local ops queue entries to resync state"
        );
        queue.clear();
    }
}
