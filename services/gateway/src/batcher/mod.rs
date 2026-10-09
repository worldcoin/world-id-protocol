//! Unified batcher abstraction: generic policy-driven batching, per-batcher
//! strategies, and command routing.

mod create;
mod ops;

pub(crate) use create::{CreateBatcher, CreateReqEnvelope};
pub(crate) use ops::{OpsBatcher, OpsEnvelope};

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use alloy::{primitives::Bytes, providers::DynProvider, rpc::types::TransactionRequest};
use tokio::{
    sync::{Mutex, mpsc},
    time::Instant,
};
use uuid::Uuid;
use world_id_primitives::api_types::{CreateAccountRequest, GatewayErrorCode, GatewayRequestState};
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{
    batch_policy::{
        BacklogUrgencyStats, BaseFeeCache, BatchPolicyEngine, DecisionReason, record_policy_metrics,
    },
    batch_type::BatchType,
    config::BatchPolicyConfig,
    error::parse_contract_error,
    metrics,
    request_tracker::BacklogScope,
    transaction_submitter::{SubmitOutcome, TransactionSubmitter},
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
    fn backlog_scope(&self) -> BacklogScope;

    /// Builds the unsigned transaction for a batch.
    fn build_tx(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: &[E],
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
    tx: mpsc::Sender<E>,
    rx: Mutex<mpsc::Receiver<E>>,
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
        let (tx, rx) = mpsc::channel(local_queue_limit.max(1));

        Self {
            tx,
            rx: Mutex::new(rx),
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
        self.tx.send(envelope).await.is_ok()
    }

    pub async fn run(&self) {
        let mut rx = self.rx.lock().await;
        self.run_policy_loop(&mut rx).await;
    }

    /// Takes ownership of a batch the policy released and submits it.
    ///
    /// Returns the batch when no wallet became available, so the caller can
    /// retry it with [`Self::try_submit`] instead of failing its requests.
    async fn dispatch(&self, batch: Vec<E>) -> Option<Vec<E>> {
        if batch.is_empty() {
            return None;
        }

        // Take ownership of the requests before waiting for a wallet: a batch
        // that is queued behind capacity must not look abandoned to the sweeper.
        // Requests already resolved elsewhere are dropped from the batch, so
        // they are never put on chain.
        let claimed: HashSet<String> = self
            .submitter
            .mark_batching(&Self::request_ids(&batch))
            .await
            .into_iter()
            .collect();
        let batch: Vec<E> = batch
            .into_iter()
            .filter(|envelope| claimed.contains(envelope.request_id()))
            .collect();
        if batch.is_empty() {
            return None;
        }
        metrics::record_batch_submitted(self.strategy.batch_type().as_str(), batch.len());

        self.try_submit(batch).await
    }

    /// Submits a batch that is already marked `Batching`.
    ///
    /// Returns the batch when no wallet became available.
    async fn try_submit(&self, batch: Vec<E>) -> Option<Vec<E>> {
        let batch_type = self.strategy.batch_type();
        let ids = Self::request_ids(&batch);
        let transaction = self.strategy.build_tx(&self.registry, &batch);

        match self
            .submitter
            .submit(transaction, ids.clone(), batch_type)
            .await
        {
            Ok(SubmitOutcome::Submitted | SubmitOutcome::Abandoned) => None,
            Ok(SubmitOutcome::NoWalletAvailable) => {
                tracing::warn!(
                    batch_type = %batch_type,
                    batch_size = ids.len(),
                    "no wallet became available; holding the batch for retry"
                );
                Some(batch)
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    batch_type = %batch_type,
                    "batch submission failed before broadcast"
                );
                let message = error.to_string();
                // Signing estimates gas, so a contract revert surfaces here and
                // keeps its specific code. Anything else (RPC, Redis) is ours,
                // not the caller's.
                let code = match parse_contract_error(&message) {
                    GatewayErrorCode::BadRequest if !message.contains("revert") => {
                        GatewayErrorCode::InternalServerError
                    }
                    code => code,
                };
                self.submitter
                    .fail_batching(&ids, GatewayRequestState::failed(message, Some(code)))
                    .await;
                None
            }
        }
    }

    fn request_ids(batch: &[E]) -> Vec<String> {
        batch
            .iter()
            .map(|envelope| envelope.request_id().to_owned())
            .collect()
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

    async fn run_policy_loop(&self, rx: &mut mpsc::Receiver<E>) {
        let mut policy_engine = BatchPolicyEngine::new(self.batch_policy.clone());
        let reeval_interval = Duration::from_millis(self.batch_policy.reeval_ms);

        let mut queue: VecDeque<TimedEnvelope<E>> = VecDeque::new();
        let mut next_eval = Instant::now() + reeval_interval;
        let mut rx_open = true;
        // A batch the policy released that is waiting only for a wallet. It is
        // kept out of `queue` so it is retried as-is: re-running the policy on
        // it could defer it indefinitely under high cost, because its requests
        // are no longer `Queued` and so contribute no urgency.
        let mut stalled: Option<Vec<E>> = None;

        while rx_open || !queue.is_empty() || stalled.is_some() {
            if queue.len() >= self.local_queue_limit {
                tracing::warn!(
                    batch_type = %self.strategy.batch_type(),
                    queue_len = queue.len(),
                    local_queue_limit = self.local_queue_limit,
                    "{} policy queue reached local capacity, pausing intake for backpressure",
                    self.strategy.batch_type()
                );
            }

            if queue.is_empty() && stalled.is_none() {
                if !rx_open {
                    break;
                }

                let maybe_first = rx.recv().await;
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
                maybe_req = rx.recv(), if can_recv => PolicyLoopEvent::Recv(maybe_req),
            };

            match event {
                PolicyLoopEvent::Tick => {
                    if let Some(batch) = stalled.take() {
                        stalled = self.try_submit(batch).await;
                        next_eval = Instant::now() + reeval_interval;
                        continue;
                    }

                    let cost_score = policy_engine.update_cost_score(self.base_fee_cache.latest());

                    let fallback_age = queue
                        .front()
                        .map(|first| Instant::now().duration_since(first.enqueued_at).as_secs())
                        .unwrap_or_default();

                    let stats = match self
                        .submitter
                        .queued_backlog_stats(self.strategy.backlog_scope())
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
                    record_policy_metrics(self.strategy.batch_type().as_str(), &decision);

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
                    stalled = self.dispatch(batch).await;

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
