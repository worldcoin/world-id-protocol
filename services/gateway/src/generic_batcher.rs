use std::sync::Arc;

use alloy::{network::Ethereum, providers::DynProvider};
use tokio::{sync::mpsc, time::Instant};
use world_id_core::{
    api_types::GatewayRequestState, world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

use crate::{
    RequestTracker, batch_policy::BaseFeeCache, config::BatchPolicyConfig,
    error::parse_contract_error, metrics, policy_batcher::PolicyBatchLoopRunner,
    request_tracker::BacklogScope,
};

/// Every envelope that can be batched must expose a request id for tracker
/// status updates.
pub(crate) trait BatcherEnvelope: Send + 'static {
    fn request_id(&self) -> &str;
}

/// Return value from a successful strategy send so the generic core can
/// update tracker state and spawn receipt tracking.
pub(crate) struct PendingBatchTx {
    pub tx_hash: String,
    pub builder: alloy::providers::PendingTransactionBuilder<Ethereum>,
}

/// Strategy trait for submitting batches
pub(crate) trait BatchSubmitStrategy<E: BatcherEnvelope>: Send + 'static {
    fn batch_type(&self) -> &'static str;
    fn backlog_scope(&self) -> BacklogScope;

    fn send_batch(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: Vec<E>,
    ) -> impl Future<Output = Result<PendingBatchTx, String>> + Send;
}

pub(crate) struct GenericBatcherRunner<E, S>
where
    E: BatcherEnvelope,
    S: BatchSubmitStrategy<E>,
{
    rx: mpsc::Receiver<E>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    max_batch_size: usize,
    local_queue_limit: usize,
    tracker: RequestTracker,
    batch_policy: BatchPolicyConfig,
    base_fee_cache: BaseFeeCache,
    strategy: S,
}

impl<E, S> GenericBatcherRunner<E, S>
where
    E: BatcherEnvelope,
    S: BatchSubmitStrategy<E>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        max_batch_size: usize,
        local_queue_limit: usize,
        rx: mpsc::Receiver<E>,
        tracker: RequestTracker,
        batch_policy: BatchPolicyConfig,
        base_fee_cache: BaseFeeCache,
        strategy: S,
    ) -> Self {
        Self {
            rx,
            registry,
            max_batch_size,
            local_queue_limit: local_queue_limit.max(1),
            tracker,
            batch_policy,
            base_fee_cache,
            strategy,
        }
    }

    pub async fn run(mut self) {
        self.run_policy_loop().await;
    }

    async fn submit_common(&self, batch: Vec<E>) {
        if batch.is_empty() {
            return;
        }

        let batch_type = self.strategy.batch_type();
        let ids: Vec<String> = batch.iter().map(|e| e.request_id().to_owned()).collect();

        metrics::record_batch_submitted(batch_type, ids.len());

        self.tracker
            .set_status_batch(&ids, GatewayRequestState::Batching)
            .await;

        let start = Instant::now();
        match self.strategy.send_batch(&self.registry, batch).await {
            Ok(sent) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                metrics::record_batch_result(batch_type, true, latency_ms);

                self.tracker
                    .set_status_batch(
                        &ids,
                        GatewayRequestState::Submitted {
                            tx_hash: sent.tx_hash.clone(),
                        },
                    )
                    .await;

                self.tracker
                    .spawn_receipt_tracker(ids, sent.builder, sent.tx_hash);
            }
            Err(error_str) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                metrics::record_batch_result(batch_type, false, latency_ms);

                tracing::error!(error = %error_str, "{batch_type} batch send failed");
                let code = parse_contract_error(&error_str);
                self.tracker
                    .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                    .await;
            }
        }
    }
}

impl<E, S> PolicyBatchLoopRunner for GenericBatcherRunner<E, S>
where
    E: BatcherEnvelope,
    S: BatchSubmitStrategy<E>,
{
    type Envelope = E;

    fn batch_type(&self) -> &'static str {
        self.strategy.batch_type()
    }

    fn backlog_scope(&self) -> BacklogScope {
        self.strategy.backlog_scope()
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
        self.submit_common(batch).await;
    }
}
