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
            self.run_policy_loop().await;
        } else {
            self.run_legacy_loop().await;
        }
    }

    async fn drop_local_queue_and_inflight(
        &self,
        queue: &mut VecDeque<TimedEnvelope<CreateReqEnvelope>>,
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

    async fn submit_create_batch(&self, batch: Vec<CreateReqEnvelope>) {
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

impl PolicyBatchLoopRunner for CreateBatcherRunner {
    type Envelope = CreateReqEnvelope;

    fn batch_type(&self) -> &'static str {
        "create"
    }

    fn backlog_scope(&self) -> BacklogScope {
        BacklogScope::Create
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
        self.submit_create_batch(batch).await;
    }

    async fn handle_no_backlog(&self, queue: &mut VecDeque<TimedEnvelope<Self::Envelope>>) {
        let dropped = queue.len();
        let inflight_removed = self.drop_local_queue_and_inflight(queue).await;
        tracing::warn!(
            dropped,
            inflight_removed,
            "redis reports no queued backlog, dropping local create queue entries to resync state"
        );
    }
}
