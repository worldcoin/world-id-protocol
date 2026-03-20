//! Unified batcher abstraction: generic policy-driven runner, per-batcher
//! strategies, and the public handle/command routing layer.

mod create;
mod ops;

pub(crate) use create::{CreateBatcherHandle, CreateBatcherRunner, CreateReqEnvelope};
pub(crate) use ops::{OpsBatcherHandle, OpsBatcherRunner, OpsEnvelope};

use std::{collections::VecDeque, sync::Arc, time::Duration};

use alloy::{network::Ethereum, primitives::Bytes, providers::DynProvider};
use tokio::{sync::mpsc, time::Instant};
use uuid::Uuid;
use world_id_core::{
    api_types::{CreateAccountRequest, GatewayRequestState},
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

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
/// Default gas estimates for operation types.
pub(super) mod defaults {
    pub const DEFAULT_CREATE_ACCOUNT_GAS: u64 = 600_000;
    pub const DEFAULT_INSERT_AUTHENTICATOR_GAS: u64 = 252_784;
    pub const DEFAULT_UPDATE_AUTHENTICATOR_GAS: u64 = 385_775;
    pub const DEFAULT_REMOVE_AUTHENTICATOR_GAS: u64 = 721_044;
    pub const DEFAULT_RECOVER_ACCOUNT_GAS: u64 = 516_400;
    /// Measured via `forge test --gas-report` (max observed: 98,027).
    /// Does not call `_updateLeafAndRecord`, so cost is tree-depth-independent.
    pub const DEFAULT_INITIATE_RECOVERY_AGENT_UPDATE_GAS: u64 = 100_000;
    /// Measured via `forge test --gas-report` (max observed: 41,313).
    /// Does not call `_updateLeafAndRecord`, so cost is tree-depth-independent.
    pub const DEFAULT_CANCEL_RECOVERY_AGENT_UPDATE_GAS: u64 = 43_000;
    /// Measured via `forge test --gas-report` (max observed: 23,537).
    /// Does not call `_updateLeafAndRecord`, so cost is tree-depth-independent.
    pub const DEFAULT_EXECUTE_RECOVERY_AGENT_UPDATE_GAS: u64 = 25_000;
}

/// Unified batcher handle that routes to the appropriate batcher.
#[derive(Clone)]
pub struct BatcherHandle {
    pub create: CreateBatcherHandle,
    pub ops: OpsBatcherHandle,
}

impl BatcherHandle {
    /// Submit a command to the appropriate batcher.
    pub async fn submit(&self, cmd: Command) -> bool {
        match cmd {
            Command::CreateAccount { id, req, .. } => {
                let envelope = CreateReqEnvelope {
                    id: id.to_string(),
                    req,
                };
                self.create.tx.send(envelope).await.is_ok()
            }
            Command::Operation { id, calldata, .. } => {
                let envelope = OpsEnvelope {
                    id: id.to_string(),
                    calldata,
                };
                self.ops.tx.send(envelope).await.is_ok()
            }
        }
    }
}

/// Unified command type for all batcher operations.
pub enum Command {
    CreateAccount {
        id: Uuid,
        req: CreateAccountRequest,
        #[allow(dead_code)]
        gas: u64,
    },
    Operation {
        id: Uuid,
        calldata: Bytes,
        #[allow(dead_code)]
        gas: u64,
    },
}

impl Command {
    /// Create a new account creation command.
    pub fn create_account(id: Uuid, req: CreateAccountRequest, gas: u64) -> Self {
        Self::CreateAccount { id, req, gas }
    }

    /// Create a new operation command (insert/update/remove/recover).
    pub fn operation(id: Uuid, calldata: Bytes, gas: u64) -> Self {
        Self::Operation { id, calldata, gas }
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
pub(crate) trait BatchSubmitStrategy<E: BatcherEnvelope>: Send + Default + 'static {
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
    ) -> Self {
        Self {
            rx,
            registry,
            max_batch_size,
            local_queue_limit: local_queue_limit.max(1),
            tracker,
            batch_policy,
            base_fee_cache,
            strategy: S::default(),
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
                            tx_hash: sent.formatted_tx_hash.clone(),
                        },
                    )
                    .await;

                self.tracker
                    .spawn_receipt_tracker(ids, sent.builder, sent.formatted_tx_hash);
            }
            Err(err) => {
                let latency_ms = start.elapsed().as_millis() as f64;
                metrics::record_batch_result(batch_type, false, latency_ms);

                let error_str = err.to_string();
                tracing::error!(error = %error_str, "{batch_type} batch send failed");
                let code = parse_contract_error(&error_str);
                self.tracker
                    .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                    .await;
            }
        }
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

// ── Public handle & command routing ─────────────────────────────────────
