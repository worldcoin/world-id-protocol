//! Unified batcher abstraction: generic policy-driven runner, per-batcher
//! strategies, the unbatched billing sender, and the public handle/command
//! routing layer.

mod billing;
mod create;
mod ops;

pub(crate) use billing::{BillingSender, BillingSenderHandle};
pub(crate) use create::{
    CreateBatcherHandle, CreateBatcherRunner, CreateReqEnvelope, CreateStrategy,
};
pub(crate) use ops::{OpsBatcherHandle, OpsBatcherRunner, OpsEnvelope, OpsStrategy};

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use alloy::{network::Ethereum, primitives::Bytes, providers::DynProvider};
use tokio::{
    sync::{Mutex, mpsc},
    time::Instant,
};
use uuid::Uuid;
use world_id_primitives::api_types::{CreateAccountRequest, GatewayRequestState};
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{
    RequestTracker,
    batch_policy::{
        BacklogUrgencyStats, BaseFeeCache, BatchPolicyEngine, DecisionReason, record_policy_metrics,
    },
    config::BatchPolicyConfig,
    error::parse_contract_error,
    metrics,
    request_tracker::BacklogScope,
};

/// Unified batcher handle that routes to the appropriate batcher.
#[derive(Clone)]
pub struct BatcherHandle {
    pub create: CreateBatcherHandle,
    pub ops: OpsBatcherHandle,
    /// `None` when no Billing Contract is configured.
    pub billing: Option<BillingSenderHandle>,
}

impl BatcherHandle {
    /// Submit a command to the appropriate batcher.
    pub async fn submit(&self, cmd: Command) -> bool {
        match cmd {
            Command::CreateAccount { id, req } => {
                let envelope = CreateReqEnvelope {
                    id: id.to_string(),
                    req,
                };
                self.create.tx.send(envelope).await.is_ok()
            }
            Command::Operation { id, calldata } => {
                let envelope = OpsEnvelope {
                    id: id.to_string(),
                    calldata,
                };
                self.ops.tx.send(envelope).await.is_ok()
            }
            Command::RegisterBilling { id, calldata } => {
                let Some(billing) = &self.billing else {
                    return false;
                };
                let envelope = OpsEnvelope {
                    id: id.to_string(),
                    calldata,
                };
                billing.tx.send(envelope).await.is_ok()
            }
        }
    }
}

/// Unified command type for all batcher operations.
pub enum Command {
    CreateAccount {
        id: Uuid,
        req: CreateAccountRequest,
    },
    Operation {
        id: Uuid,
        calldata: Bytes,
    },
    /// A `WorldIDBilling.register` call, sent on its own as soon as it arrives.
    RegisterBilling {
        id: Uuid,
        calldata: Bytes,
    },
}

impl Command {
    /// Create a new account creation command.
    pub fn create_account(id: Uuid, req: CreateAccountRequest) -> Self {
        Self::CreateAccount { id, req }
    }

    /// Create a new operation command (insert/update/remove/recover).
    pub fn operation(id: Uuid, calldata: Bytes) -> Self {
        Self::Operation { id, calldata }
    }

    /// Create a new billing registration command.
    pub fn register_billing(id: Uuid, calldata: Bytes) -> Self {
        Self::RegisterBilling { id, calldata }
    }
}

// ── Generic batcher core ────────────────────────────────────────────────

/// Every envelope that can be batched must expose a request id for tracker
/// status updates.
pub(crate) trait BatcherEnvelope: Send + 'static {
    fn request_id(&self) -> &str;
}

/// Return value from a successful [`BatchSubmitStrategy::send_batch`] call.
pub(crate) struct PendingBatchTx {
    // Hex formatted transaction hash
    pub formatted_tx_hash: String,
    // Handle for pending transaction tracking
    pub builder: alloy::providers::PendingTransactionBuilder<Ethereum>,
}

impl PendingBatchTx {
    pub fn new(builder: alloy::providers::PendingTransactionBuilder<Ethereum>) -> Self {
        Self {
            formatted_tx_hash: format!("0x{:x}", builder.tx_hash()),
            builder,
        }
    }
}

/// Strategy trait that captures the only per-batcher differences:
///   - batch label / backlog scope (for metrics / policy)
///   - the actual on-chain send call
pub(crate) trait BatchSubmitStrategy<E: BatcherEnvelope>: Send + 'static {
    fn batch_type(&self) -> &'static str;
    fn backlog_scope(&self) -> BacklogScope;

    fn send_batch(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: Vec<E>,
    ) -> impl Future<Output = Result<PendingBatchTx, alloy::contract::Error>> + Send;
}

struct TimedEnvelope<T> {
    enqueued_at: Instant,
    envelope: T,
}

enum PolicyLoopEvent<T> {
    Tick,
    Recv(Option<T>),
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
    tx_send_lock: Arc<Mutex<()>>,
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
        tx_send_lock: Arc<Mutex<()>>,
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
            tx_send_lock,
            strategy,
        }
    }

    pub async fn run(mut self) {
        self.run_policy_loop().await;
    }

    async fn submit_common(&self, batch: Vec<E>) {
        let batch_type = self.strategy.batch_type();
        let Some((batch, ids)) = claim_requests(&self.tracker, batch_type, batch).await else {
            return;
        };
        send_claimed(
            &self.tracker,
            &self.tx_send_lock,
            batch_type,
            ids,
            self.strategy.send_batch(&self.registry, batch),
        )
        .await;
    }

    fn handle_no_backlog(&self, queue: &mut VecDeque<TimedEnvelope<E>>) {
        let dropped = queue.len();
        tracing::warn!(
            batch_type = self.strategy.batch_type(),
            dropped,
            "redis reports no queued backlog, dropping local queue entries to resync state"
        );
        queue.clear();
    }

    async fn run_policy_loop(&mut self) {
        let mut policy_engine = BatchPolicyEngine::new(self.batch_policy.clone());
        let reeval_interval = Duration::from_millis(self.batch_policy.reeval_ms);

        let mut queue: VecDeque<TimedEnvelope<E>> = VecDeque::new();
        let mut next_eval = Instant::now() + reeval_interval;
        let mut rx_open = true;

        while rx_open || !queue.is_empty() {
            if queue.len() >= self.local_queue_limit {
                tracing::warn!(
                    batch_type = self.strategy.batch_type(),
                    queue_len = queue.len(),
                    local_queue_limit = self.local_queue_limit,
                    "{} policy queue reached local capacity, pausing intake for backpressure",
                    self.strategy.batch_type()
                );
            }

            if queue.is_empty() {
                if !rx_open {
                    break;
                }

                let maybe_first = self.rx.recv().await;
                match maybe_first {
                    Some(first) => {
                        queue.push_back(TimedEnvelope {
                            enqueued_at: Instant::now(),
                            envelope: first,
                        });
                        next_eval = Instant::now() + reeval_interval;
                    }
                    None => {
                        tracing::info!("{} batcher channel closed", self.strategy.batch_type());
                        rx_open = false;
                    }
                }
                continue;
            }

            let can_recv = rx_open && queue.len() < self.local_queue_limit;
            let event = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(next_eval) => PolicyLoopEvent::Tick,
                maybe_req = self.rx.recv(), if can_recv => PolicyLoopEvent::Recv(maybe_req),
            };

            match event {
                PolicyLoopEvent::Tick => {
                    let cost_score = policy_engine.update_cost_score(self.base_fee_cache.latest());

                    let fallback_age = queue
                        .front()
                        .map(|first| Instant::now().duration_since(first.enqueued_at).as_secs())
                        .unwrap_or_default();

                    let stats = match self
                        .tracker
                        .queued_backlog_stats_for_scope(self.strategy.backlog_scope())
                        .await
                    {
                        Ok(stats) => stats,
                        Err(err) => {
                            tracing::warn!(
                                batch_type = self.strategy.batch_type(),
                                error = %err,
                                "failed to read queued backlog stats; using local fallback"
                            );
                            BacklogUrgencyStats {
                                queued_count: queue.len(),
                                oldest_age_secs: fallback_age,
                            }
                        }
                    };

                    let decision = policy_engine.evaluate(stats, self.max_batch_size, cost_score);
                    record_policy_metrics(self.strategy.batch_type(), &decision);

                    if !decision.should_send {
                        if matches!(decision.reason, DecisionReason::NoBacklog) && !queue.is_empty()
                        {
                            self.handle_no_backlog(&mut queue);
                        }
                        next_eval = Instant::now() + reeval_interval;
                        continue;
                    }

                    let take_n = decision.target_batch_size.min(queue.len()).max(1);
                    let batch = queue.drain(..take_n).map(|timed| timed.envelope).collect();
                    self.submit_common(batch).await;

                    next_eval = Instant::now() + reeval_interval;
                }
                PolicyLoopEvent::Recv(maybe_req) => match maybe_req {
                    Some(req) => {
                        queue.push_back(TimedEnvelope {
                            enqueued_at: Instant::now(),
                            envelope: req,
                        });
                    }
                    None => {
                        tracing::info!(
                            "{} batcher channel closed while policy batching",
                            self.strategy.batch_type()
                        );
                        rx_open = false;
                    }
                },
            }
        }
    }
}

// ── Shared submission path ──────────────────────────────────────────────

/// Moves `batch`'s requests from `Queued` to `Batching` and keeps only the ones that were still
/// queued.
///
/// The orphan sweeper may already have failed a request that is still in a local queue; sending
/// it would act on a request its client was told failed (and an expired billing registration
/// would revert). Returns `None` when nothing is left to send, including when Redis is
/// unreachable: the requests then stay `Queued` and the sweeper fails them.
pub(crate) async fn claim_requests<E: BatcherEnvelope>(
    tracker: &RequestTracker,
    batch_type: &'static str,
    batch: Vec<E>,
) -> Option<(Vec<E>, Vec<String>)> {
    if batch.is_empty() {
        return None;
    }
    let ids: Vec<String> = batch.iter().map(|e| e.request_id().to_owned()).collect();

    let claimed = match tracker.claim_for_batching(&ids).await {
        Ok(claimed) => claimed,
        Err(error) => {
            tracing::error!(
                %error,
                batch_type,
                batch_size = ids.len(),
                request_ids = ?ids,
                "failed to claim batch requests in Redis; dropping batch, the orphan sweeper will fail them"
            );
            metrics::record_batch_requests_skipped(batch_type, "claim_error", ids.len());
            return None;
        }
    };

    let claimed_set: HashSet<&str> = claimed.iter().map(String::as_str).collect();
    if claimed.len() < ids.len() {
        let skipped: Vec<&str> = ids
            .iter()
            .map(String::as_str)
            .filter(|id| !claimed_set.contains(id))
            .collect();
        tracing::warn!(
            batch_type,
            skipped = skipped.len(),
            request_ids = ?skipped,
            "skipping batch requests that are no longer queued (likely failed by the orphan sweeper)"
        );
        metrics::record_batch_requests_skipped(batch_type, "not_queued", skipped.len());
    }

    if claimed.is_empty() {
        return None;
    }

    let batch = batch
        .into_iter()
        .filter(|e| claimed_set.contains(e.request_id()))
        .collect();
    Some((batch, claimed))
}

/// Sends one transaction for the claimed requests `ids` under the gateway's send lock, marks them
/// `Submitted` and tracks the receipt, or fails them if the RPC send fails.
///
/// Every sender shares one signer, so `tx_send_lock` keeps their nonces in order.
pub(crate) async fn send_claimed(
    tracker: &RequestTracker,
    tx_send_lock: &Mutex<()>,
    batch_type: &'static str,
    ids: Vec<String>,
    send: impl Future<Output = Result<PendingBatchTx, alloy::contract::Error>>,
) {
    metrics::record_batch_submitted(batch_type, ids.len());

    let _send_guard = tx_send_lock.lock().await;
    let start = Instant::now();
    match send.await {
        Ok(sent) => {
            // Record only the RPC send latency here.  The on-chain outcome
            // (success / failure / confirmation latency) is recorded later
            // in `spawn_receipt_tracker` once the receipt is obtained.
            let send_latency_ms = start.elapsed().as_millis() as f64;
            metrics::record_batch_send_latency(batch_type, send_latency_ms);

            tracing::info!(
                tx_hash = %sent.formatted_tx_hash,
                batch_type,
                batch_size = ids.len(),
                send_latency_ms,
                "batch transaction submitted to RPC node"
            );

            tracker
                .set_status_batch(
                    &ids,
                    GatewayRequestState::Submitted {
                        tx_hash: sent.formatted_tx_hash.clone(),
                    },
                )
                .await;

            tracker.spawn_receipt_tracker(
                ids,
                sent.builder,
                sent.formatted_tx_hash,
                batch_type,
                start,
            );
        }
        Err(err) => {
            let send_latency_ms = start.elapsed().as_millis() as f64;
            metrics::record_batch_send_failed(batch_type, send_latency_ms);

            let error_str = err.to_string();
            tracing::error!(
                error = %error_str,
                batch_type,
                send_latency_ms,
                "{batch_type} batch failed to submit to RPC node"
            );
            let code = parse_contract_error(&error_str);
            tracker
                .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                .await;
        }
    }
}

// ── Public handle & command routing ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use alloy::{
        primitives::Address,
        providers::{Provider as _, ProviderBuilder},
    };
    use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestKind};

    use super::*;

    struct TestEnvelope(String);

    impl BatcherEnvelope for TestEnvelope {
        fn request_id(&self) -> &str {
            &self.0
        }
    }

    /// Records the request IDs of every batch it is asked to send, then fails
    /// the send so no RPC is needed.
    #[derive(Clone, Default)]
    struct RecordingStrategy {
        sent: Arc<StdMutex<Vec<Vec<String>>>>,
    }

    impl BatchSubmitStrategy<TestEnvelope> for RecordingStrategy {
        fn batch_type(&self) -> &'static str {
            "test"
        }

        fn backlog_scope(&self) -> BacklogScope {
            BacklogScope::All
        }

        async fn send_batch(
            &self,
            _registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
            batch: Vec<TestEnvelope>,
        ) -> Result<PendingBatchTx, alloy::contract::Error> {
            self.sent
                .lock()
                .unwrap()
                .push(batch.into_iter().map(|e| e.0).collect());
            Err(alloy::contract::Error::ContractNotDeployed)
        }
    }

    /// A request the orphan sweeper fails while it is still in the local queue
    /// is never sent, and keeps its sweeper status; the rest of its batch is sent.
    #[tokio::test]
    async fn swept_request_is_not_sent() {
        let (_redis, redis_url) = world_id_test_utils::redis_testcontainer()
            .await
            .expect("failed to start Redis");
        let tracker = RequestTracker::new(redis_url, None, 60).await;

        let ids = ["queued-1", "swept", "queued-2"].map(String::from);
        for id in &ids {
            tracker
                .new_request_with_id(id.clone(), GatewayRequestKind::InsertAuthenticator, vec![])
                .await
                .unwrap();
        }
        let swept_status = GatewayRequestState::failed(
            "request timed out in queued state due to unexpected error",
            Some(GatewayErrorCode::InternalServerError),
        );
        tracker.set_status("swept", swept_status).await;

        let provider = ProviderBuilder::new()
            .connect_http("http://127.0.0.1:1".parse().unwrap())
            .erased();
        let registry = Arc::new(WorldIdRegistryInstance::new(
            Address::ZERO,
            Arc::new(provider),
        ));
        let strategy = RecordingStrategy::default();
        let (tx, rx) = mpsc::channel(8);
        let runner = GenericBatcherRunner::new(
            registry,
            10,
            100,
            rx,
            tracker.clone(),
            BatchPolicyConfig {
                reeval_ms: 10,
                ..Default::default()
            },
            BaseFeeCache::default(),
            Arc::new(Mutex::new(())),
            strategy.clone(),
        );
        for id in &ids {
            tx.send(TestEnvelope(id.clone())).await.unwrap();
        }
        drop(tx);
        tokio::time::timeout(Duration::from_secs(10), runner.run())
            .await
            .expect("batcher did not drain its queue");

        assert_eq!(
            *strategy.sent.lock().unwrap(),
            vec![vec!["queued-1".to_string(), "queued-2".to_string()]]
        );
        let swept = tracker.snapshot("swept").await.unwrap();
        assert!(matches!(
            swept.status,
            GatewayRequestState::Failed {
                error_code: Some(GatewayErrorCode::InternalServerError),
                ..
            }
        ));
        for id in ["queued-1", "queued-2"] {
            let record = tracker.snapshot(id).await.unwrap();
            assert!(
                matches!(record.status, GatewayRequestState::Failed { .. }),
                "{id} should carry the send failure, got {:?}",
                record.status
            );
        }
    }
}
