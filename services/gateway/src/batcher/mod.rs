//! Unified batcher abstraction: generic policy-driven batching, per-batcher
//! strategies, and command routing.

mod create;
mod ops;

pub(crate) use create::{CreateBatcher, CreateReqEnvelope};
pub(crate) use ops::{OpsBatcher, OpsEnvelope};

use std::{collections::VecDeque, sync::Arc, time::Duration};

use alloy::{primitives::Bytes, providers::DynProvider, rpc::types::TransactionRequest};
use tokio::time::Instant;
use uuid::Uuid;
use world_id_primitives::api_types::{CreateAccountRequest, GatewayRequestState};
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{
    batch_policy::{
        BacklogUrgencyStats, BaseFeeCache, BatchPolicyEngine, DecisionReason, record_policy_metrics,
    },
    batch_type::BatchType,
    config::BatchPolicyConfig,
    error::parse_contract_error,
    metrics,
    transaction_submitter::TransactionSubmitter,
};

/// Unified batcher component that routes commands to the appropriate queue.
#[derive(Clone)]
pub struct Batcher {
    pub(crate) create: Arc<CreateBatcher>,
    pub(crate) ops: Arc<OpsBatcher>,
}

impl Batcher {
    /// Submit a command to the appropriate batcher.
    pub async fn submit(&self, cmd: Command) -> bool {
        match cmd {
            Command::CreateAccount { id, req } => {
                let envelope = CreateReqEnvelope {
                    id: id.to_string(),
                    req,
                };
                self.create.enqueue(envelope).await
            }
            Command::Operation { id, calldata } => {
                let envelope = OpsEnvelope {
                    id: id.to_string(),
                    calldata,
                };
                self.ops.enqueue(envelope).await
            }
        }
    }
}

/// Unified command type for all batcher operations.
pub enum Command {
    CreateAccount { id: Uuid, req: CreateAccountRequest },
    Operation { id: Uuid, calldata: Bytes },
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
}

// ── Generic batcher core ────────────────────────────────────────────────

/// Every envelope that can be batched must expose a request id for tracker
/// status updates.
pub(crate) trait BatcherEnvelope: Send + 'static {
    fn request_id(&self) -> &str;
}

/// Strategy trait that captures the per-batcher transaction construction.
pub(crate) trait BatchSubmitStrategy<E: BatcherEnvelope>:
    Send + Sync + Default + 'static
{
    fn batch_type(&self) -> BatchType;

    fn build_tx(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: Vec<E>,
    ) -> TransactionRequest;
}

struct TimedEnvelope<T> {
    enqueued_at: Instant,
    envelope: T,
}

enum PolicyLoopEvent<T> {
    Tick,
    Recv(Option<T>),
}

pub(crate) struct GenericBatcher<E, S>
where
    E: BatcherEnvelope,
    S: BatchSubmitStrategy<E>,
{
    tx: flume::Sender<E>,
    rx: flume::Receiver<E>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    submitter: Arc<TransactionSubmitter>,
    max_batch_size: usize,
    local_queue_limit: usize,
    batch_policy: BatchPolicyConfig,
    base_fee_cache: BaseFeeCache,
    strategy: S,
}

impl<E, S> GenericBatcher<E, S>
where
    E: BatcherEnvelope,
    S: BatchSubmitStrategy<E>,
{
    pub fn new(
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        submitter: Arc<TransactionSubmitter>,
        max_batch_size: usize,
        local_queue_limit: usize,
        batch_policy: BatchPolicyConfig,
        base_fee_cache: BaseFeeCache,
    ) -> Self {
        let (tx, rx) = flume::bounded(local_queue_limit.max(1));

        Self {
            tx,
            rx,
            registry,
            submitter,
            max_batch_size,
            local_queue_limit: local_queue_limit.max(1),
            batch_policy,
            base_fee_cache,
            strategy: S::default(),
        }
    }

    pub async fn enqueue(&self, envelope: E) -> bool {
        self.tx.send_async(envelope).await.is_ok()
    }

    pub async fn run(&self) {
        self.run_policy_loop().await;
    }

    async fn submit_common(&self, batch: Vec<E>) {
        if batch.is_empty() {
            return;
        }

        let batch_type = self.strategy.batch_type();
        let ids: Vec<String> = batch.iter().map(|e| e.request_id().to_owned()).collect();

        metrics::record_batch_submitted(batch_type, ids.len());

        self.submitter
            .set_status_batch(&ids, GatewayRequestState::Batching)
            .await;

        let transaction = self.strategy.build_tx(&self.registry, batch);
        if let Err(error) = self
            .submitter
            .submit(transaction, ids.clone(), batch_type)
            .await
        {
            self.submitter
                .set_status_batch(
                    &ids,
                    GatewayRequestState::failed(
                        error.to_string(),
                        Some(parse_contract_error(&error.to_string())),
                    ),
                )
                .await;
        }
    }

    fn handle_no_backlog(&self, queue: &mut VecDeque<TimedEnvelope<E>>) {
        let dropped = queue.len();
        tracing::warn!(
            batch_type = %self.strategy.batch_type(),
            dropped,
            "redis reports no queued backlog, dropping local queue entries to resync state"
        );
        queue.clear();
    }

    async fn run_policy_loop(&self) {
        let mut policy_engine = BatchPolicyEngine::new(self.batch_policy.clone());
        let reeval_interval = Duration::from_millis(self.batch_policy.reeval_ms);

        let mut queue: VecDeque<TimedEnvelope<E>> = VecDeque::new();
        let mut next_eval = Instant::now() + reeval_interval;
        let mut rx_open = true;

        while rx_open || !queue.is_empty() {
            if queue.len() >= self.local_queue_limit {
                tracing::warn!(
                    batch_type = %self.strategy.batch_type(),
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

                let maybe_first = self.rx.recv_async().await.ok();
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
                maybe_req = self.rx.recv_async(), if can_recv => PolicyLoopEvent::Recv(maybe_req.ok()),
            };

            match event {
                PolicyLoopEvent::Tick => {
                    let cost_score = policy_engine.update_cost_score(self.base_fee_cache.latest());

                    let fallback_age = queue
                        .front()
                        .map(|first| Instant::now().duration_since(first.enqueued_at).as_secs())
                        .unwrap_or_default();

                    let stats = match self
                        .submitter
                        .queued_backlog_stats(self.strategy.batch_type())
                        .await
                    {
                        Ok(stats) => stats,
                        Err(err) => {
                            tracing::warn!(
                                batch_type = %self.strategy.batch_type(),
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
