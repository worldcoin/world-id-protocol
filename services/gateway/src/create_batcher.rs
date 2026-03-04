use std::sync::Arc;

use crate::{
    RequestTracker, batch_policy::BaseFeeCache, config::BatchPolicyConfig,
    error::parse_contract_error, metrics, policy_batcher::PolicyBatchLoopRunner,
    request_tracker::BacklogScope,
};
use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use tokio::{sync::mpsc, time::Instant};
use world_id_core::{
    api_types::{CreateAccountRequest, GatewayRequestState},
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
        self.run_policy_loop().await;
    }

    async fn submit_create_batch(&self, batch: Vec<CreateReqEnvelope>) {
        if batch.is_empty() {
            return;
        }

        let batch_size = batch.len();
        let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();

        metrics::record_batch_submitted("create", batch_size);

        self.tracker
            .set_status_batch(&ids, GatewayRequestState::Batching)
            .await;

        let mut recovery_addresses: Vec<Address> = Vec::new();
        let mut auths: Vec<Vec<Address>> = Vec::new();
        let mut pubkeys: Vec<Vec<U256>> = Vec::new();
        let mut commits: Vec<U256> = Vec::new();

        for env in batch {
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
                metrics::record_batch_result("create", true, latency_ms);

                let hash = format!("0x{:x}", builder.tx_hash());
                self.tracker
                    .set_status_batch(
                        &ids,
                        GatewayRequestState::Submitted {
                            tx_hash: hash.clone(),
                        },
                    )
                    .await;

                self.tracker.spawn_receipt_tracker(ids, builder, hash);
            }
            Err(err) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                metrics::record_batch_result("create", false, latency_ms);

                tracing::error!(error = %err, "create batch send failed");
                let error_str = err.to_string();
                let code = parse_contract_error(&error_str);
                self.tracker
                    .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                    .await;
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
}
