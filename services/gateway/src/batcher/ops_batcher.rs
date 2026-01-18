use crate::batcher::SignupFifoOrdering;
use crate::batcher::adaptive::{AdaptiveConfig, AdaptiveSizer};
use crate::batcher::chain_monitor::{ChainMonitor, ChainMonitorConfig};
use crate::batcher::controller::{
    shutdown_signal, spawn_critical, BatchResult, Controller, ControllerConfig, PanickedTaskError,
    ReadyBatch, Shutdown, Signal,
};
use crate::batcher::ingress::{IngressConfig, IngressController};
use crate::batcher::metrics::OpsBatcherMetrics;
use crate::batcher::order::OrderingPolicy;
use crate::batcher::pending_batch::PendingBatchConfig;
use crate::batcher::pool::{OpPool, OpPoolConfig, StatusBatcherHooks};
use crate::batcher::status_batcher::{
    StatusBatcher, StatusBatcherConfig, StatusFlusherHandle, StatusUpdate,
};
use crate::batcher::types::{FailureReason, FinalizedBatch, OpEnvelopeInner, OpStatus};
use crate::request_tracker::RequestTracker;
use alloy::primitives::U256;
use alloy::providers::{DynProvider, Provider};
use alloy::pubsub::PubSubConnect;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::Instrument;
use world_id_core::types::GatewayErrorCode;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

/// Configuration for the OpsBatcher
#[derive(Clone)]
pub struct OpsBatcherConfig {
    /// Batch window duration (how long to wait before checking for batching)
    pub batch_window: Duration,
    /// Maximum concurrent batches in flight
    pub max_concurrent_batches: usize,
    /// Adaptive sizing configuration
    pub adaptive: AdaptiveConfig,
    /// Pending batch configuration (created with registry at runtime)
    pub pending_batch: PendingBatchConfig,
    /// Chain monitor configuration
    pub chain_monitor: ChainMonitorConfig,
    /// Ingress controller configuration (backpressure, channel sizing)
    pub ingress: IngressConfig,
    /// Status batcher configuration
    pub status_batcher: StatusBatcherConfig,
    /// Operation pool configuration
    pub pool: OpPoolConfig,
    /// Maintenance interval (flush status, update metrics)
    pub maintenance_interval: Duration,
}

impl OpsBatcherConfig {
    /// Create a new config with the required registry
    pub fn new(registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>) -> Self {
        Self {
            batch_window: Duration::from_millis(1000),
            max_concurrent_batches: 3,
            adaptive: AdaptiveConfig::default(),
            pending_batch: PendingBatchConfig::new(registry),
            chain_monitor: ChainMonitorConfig::default(),
            ingress: IngressConfig::default(),
            status_batcher: StatusBatcherConfig::default(),
            pool: OpPoolConfig::default(),
            maintenance_interval: Duration::from_millis(100),
        }
    }
}

/// Main batcher coordinating all operations.
///
/// Generic over:
/// - `Prov`: The blockchain provider type
/// - `Policy`: The ordering policy that determines how operations are prioritized
///
/// # Non-blocking Design
///
/// The main `run()` loop is fully non-blocking:
/// - Status updates are batched and flushed asynchronously via `StatusBatcher`
/// - Batch spawning is permit-gated via `SpawnController`
/// - All blocking tracker operations are moved to background tasks
/// - Operation lifecycle is managed by `OpPool` with automatic status updates via hooks
pub struct OpsBatcher<
    P = DynProvider,
    WS = DynProvider,
    Policy: OrderingPolicy<T = OpEnvelopeInner> = SignupFifoOrdering<OpEnvelopeInner>,
> {
    /// Configuration
    config: OpsBatcherConfig,
    /// Provider for chain interaction (erased for spawned tasks)
    provider: Arc<DynProvider>,
    /// Chain state monitor
    chain_monitor: Arc<ChainMonitor<P, WS>>,
    /// Adaptive batch sizer
    sizer: AdaptiveSizer,
    /// Operation pool with lifecycle hooks for automatic status updates
    pool: Arc<OpPool<Policy, StatusBatcherHooks>>,
    /// Controller for batch tasks
    controller: Controller,
    /// Status batcher for non-blocking tracker updates
    status_batcher: StatusBatcher,
    /// Receiver for new operations
    op_rx: mpsc::Receiver<OpEnvelopeInner>,
    /// Metrics
    metrics: OpsBatcherMetrics,
    /// Shutdown signal
    shutdown: Shutdown,
    /// Panic receiver for critical task failures
    _abort: mpsc::UnboundedReceiver<PanickedTaskError>,
    /// Status flusher handle (for graceful shutdown)
    _status_flusher: StatusFlusherHandle,
}

impl<
        Prov: Provider + Clone + Send + Sync + 'static,
        WS: Provider + PubSubConnect + Clone + Send + Sync + 'static,
        Policy: OrderingPolicy<T = OpEnvelopeInner>,
    > OpsBatcher<Prov, WS, Policy>
{
    /// Create a new OpsBatcher and return a handle for submitting operations.
    ///
    /// The returned `IngressController` provides backpressure-aware submission
    /// methods (`try_submit` and `submit_with_backpressure`).
    ///
    /// Also returns a `Signal` that can be used to trigger shutdown.
    pub fn new(
        provider: Arc<Prov>,
        ws_provider: Option<Arc<WS>>,
        tracker: Arc<RequestTracker>,
        config: OpsBatcherConfig,
        metrics: OpsBatcherMetrics,
    ) -> (Self, IngressController, Signal) {
        // Create the channel with size from ingress config
        let (tx, rx) = mpsc::channel(config.ingress.max_depth);

        // Create the ingress controller with backpressure support
        let handle = IngressController::new(tx, config.ingress.clone());

        // Create shutdown signal pair
        let (signal, shutdown) = shutdown_signal();

        // Create panic channel
        let (_abort_sender, _abort) = mpsc::unbounded_channel();

        // Create chain monitor
        let chain_monitor =
            ChainMonitor::new(provider.clone(), ws_provider, config.chain_monitor.clone());
        let sizer = AdaptiveSizer::new(config.adaptive.clone());

        // Create status batcher with background flusher
        let (status_batcher, status_flusher) =
            StatusBatcher::new(tracker, config.status_batcher.clone());

        // Create pool with StatusBatcherHooks for automatic lifecycle updates
        let hooks = StatusBatcherHooks::new(status_batcher.clone());
        let pool = Arc::new(OpPool::with_hooks(config.pool.clone(), hooks));

        // Create status update channel for spawn controller
        let (status_tx, mut status_rx) = mpsc::channel::<StatusUpdate>(1024);

        // Spawn a task to forward status updates to the batcher
        let status_batcher_clone = status_batcher.clone();
        let forward_shutdown = shutdown.clone();
        let forward_panic_tx = _abort_sender.clone();
        spawn_critical(
            "status_forwarder",
            forward_shutdown,
            forward_panic_tx,
            async move {
                while let Some(update) = status_rx.recv().await {
                    status_batcher_clone.push(update);
                }
            },
        );

        // Create controller config
        let controller_config = ControllerConfig {
            max_concurrent: config.max_concurrent_batches,
            pending_batch: config.pending_batch.clone(),
        };

        // Erase provider type for controller
        let dyn_provider: Arc<DynProvider> = Arc::new(provider.clone().erased());

        // Create controller
        let controller = Controller::new(
            dyn_provider.clone(),
            controller_config,
            status_tx,
            metrics.clone(),
            shutdown.clone(),
            _abort_sender.clone(),
        );

        let batcher = Self {
            provider: dyn_provider,
            chain_monitor,
            sizer,
            pool,
            controller,
            status_batcher,
            op_rx: rx,
            metrics,
            shutdown,
            _abort,
            _status_flusher: status_flusher,
            config,
        };

        (batcher, handle, signal)
    }

    /// Run the batcher main loop.
    ///
    /// This loop is fully non-blocking - all potentially blocking operations
    /// are handled by background tasks or non-blocking channels.
    pub async fn run(mut self) {
        let span = tracing::info_span!("ops_batcher", policy = Policy::name(),);

        async {
            // Start chain monitor as a critical task
            let _monitor_shutdown = self.shutdown.clone();
            let chain_monitor = self.chain_monitor.clone();
            // Note: ChainMonitor needs to be updated to use our Shutdown type
            // For now, we just spawn it without the critical wrapper
            tokio::spawn(async move {
                // TODO: Update ChainMonitor to use Shutdown instead of broadcast
                let (_tx, rx) = tokio::sync::broadcast::channel::<()>(1);
                chain_monitor.run(rx).await;
            });

            let mut batch_interval = tokio::time::interval(self.config.batch_window);
            batch_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut maintenance_interval = tokio::time::interval(self.config.maintenance_interval);
            maintenance_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            tracing::info!(
                batch_window_ms = self.config.batch_window.as_millis(),
                max_concurrent = self.config.max_concurrent_batches,
                maintenance_ms = self.config.maintenance_interval.as_millis(),
                "ops_batcher.started"
            );

            loop {
                tokio::select! {
                    biased;

                    // Priority 1: Critical task panicked - trigger shutdown
                    Some(panic_error) = self._abort.recv() => {
                        tracing::error!(
                            task = panic_error.task_name(),
                            error = ?panic_error.error(),
                            "ops_batcher.critical_task_panicked"
                        );
                        // Flush any pending status updates before shutdown
                        self.status_batcher.flush();
                        break;
                    }

                    // Priority 2: Shutdown signal
                    _ = self.shutdown.clone() => {
                        tracing::info!("ops_batcher.shutdown_received");
                        break;
                    }

                    // Priority 3: Batch completions (release permits for pending spawns)
                    Some(result) = self.controller.next_completion() => {
                        match result {
                            Ok(batch_result) => {
                                self.handle_batch_result(batch_result).await;
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "ops_batcher.batch_task_join_error");
                                self.metrics.inc_batches_failed();
                            }
                        }
                        // Drain any pending spawns now that a permit is free
                        self.controller.drain_pending();
                    }

                    // Priority 4: New operations
                    Some(op) = self.op_rx.recv() => {
                        self.handle_new_op(op);
                    }

                    // Priority 5: Batch timer - try to spawn a batch
                    _ = batch_interval.tick() => {
                        self.maybe_spawn_batch().await;
                    }

                    // Priority 6: Maintenance (flush status, update metrics)
                    _ = maintenance_interval.tick() => {
                        self.status_batcher.maybe_flush();
                        self.update_metrics().await;
                    }
                }
            }

            // Graceful shutdown: drain in-flight batches
            self.graceful_shutdown().await;
        }
        .instrument(span)
        .await
    }

    /// Graceful shutdown: drain in-flight batches and flush status updates.
    async fn graceful_shutdown(&mut self) {
        tracing::info!(
            in_flight = self.controller.in_flight_count(),
            pending = self.controller.pending_count(),
            "ops_batcher.draining_batches"
        );

        // Drain all in-flight batches
        let results = self.controller.drain_in_flight().await;
        for result in results {
            self.handle_batch_result(result).await;
        }

        // Final flush of status updates
        self.status_batcher.flush();

        tracing::info!("ops_batcher.shutdown_complete");
    }

    /// Handle a new incoming operation (non-blocking).
    ///
    /// Submits the operation to the pool, which handles:
    /// - Fast validation (signature, nonce)
    /// - Status updates via hooks (on_received, on_validated)
    /// - Adding to the ready queue for batching
    fn handle_new_op(&mut self, op: OpEnvelopeInner) {
        let op_type = op.op.type_name();
        let op_id = op.id;
        self.metrics.inc_ops_received(op_type);

        tracing::debug!(
            op_id = %op_id,
            op_type = op_type,
            signer = %op.signer,
            nonce = %op.nonce,
            "op.received"
        );

        // Submit to pool - this validates and fires lifecycle hooks
        // The pool's StatusBatcherHooks will automatically update status
        let pool = self.pool.clone();
        tokio::spawn(async move {
            match pool.submit(op).await {
                Ok(_) => {
                    tracing::debug!(op_id = %op_id, "op.submitted_to_pool");
                }
                Err(e) => {
                    tracing::warn!(
                        op_id = %op_id,
                        error = %e,
                        "op.pool_submit_failed"
                    );
                    // The pool's on_failed hook will update status
                }
            }
        });
    }

    /// Maybe spawn a new batch if conditions are met (non-blocking).
    ///
    /// Uses `SpawnController` for permit-gated spawning - if no permits are
    /// available, the batch is queued for later spawning.
    async fn maybe_spawn_batch(&mut self) {
        let ready_count = self.pool.ready_count().await;
        if ready_count == 0 {
            return;
        }

        // Get current chain state
        let chain_state = self.chain_monitor.current_state();

        // Update chain metrics
        self.metrics.set_base_fee_gwei(chain_state.base_fee_gwei());
        self.metrics.set_base_fee_trend(chain_state.base_fee_trend);
        self.metrics
            .set_block_utilization(chain_state.recent_utilization);

        // Calculate batch size
        let decision = self.sizer.batch_size(&chain_state, ready_count);

        // Update adaptive metrics
        self.metrics
            .set_target_utilization(decision.utilization_target);
        self.metrics.set_fee_pressure(decision.fee_pressure);
        self.metrics.set_queue_pressure(decision.queue_pressure);
        self.metrics.set_net_pressure(decision.net_pressure);

        if decision.batch_size == 0 {
            tracing::debug!(
                reason = ?decision.reason,
                "batch.skipped_sizing"
            );
            return;
        }

        // Take operations from pool for batching
        // The pool handles nonce ordering internally
        let ops = self.pool.take_batch(decision.batch_size).await;
        if ops.is_empty() {
            tracing::debug!("batch.no_ready_ops");
            return;
        }

        // Generate batch ID and mark ops as batched
        let batch_id = uuid::Uuid::new_v4();
        let op_ids: Vec<uuid::Uuid> = ops.iter().map(|op| op.id).collect();
        self.pool.mark_batched(&op_ids, batch_id).await;

        let gas_budget = decision.gas_budget;

        // Create ReadyBatch and submit to SpawnController
        // The SpawnController handles permit acquisition and status updates
        let ready_batch = ReadyBatch::new(ops, gas_budget);
        let spawned = self.controller.try_spawn(ready_batch);

        if !spawned {
            tracing::debug!(
                pending = self.controller.pending_count(),
                "batch.queued_no_permits"
            );
        }
    }

    /// Handle a batch result (non-blocking).
    ///
    /// Handles both completed batches and shutdown cancellations.
    async fn handle_batch_result(&mut self, result: BatchResult) {
        match result {
            BatchResult::Completed(batch) => self.handle_finalized_batch(batch).await,
            BatchResult::Shutdown { batch_id } => {
                tracing::debug!(batch_id = %batch_id, "batch.cancelled_shutdown");
            }
        }
    }

    /// Handle a finalized batch.
    ///
    /// Updates pool lifecycle state and metrics.
    async fn handle_finalized_batch(&mut self, batch: FinalizedBatch) {
        tracing::info!(
            batch_id = %batch.batch_id,
            tx_hash = ?batch.tx_hash,
            success = batch.success_count(),
            failed = batch.failure_count(),
            evicted = batch.evicted_count(),
            duration_ms = batch.timing.total_duration.as_millis(),
            "batch.finalized"
        );

        // Record metrics
        self.metrics
            .observe_batch_duration(batch.timing.total_duration.as_secs_f64());

        if batch.tx_hash.is_some() {
            self.metrics.inc_ops_finalized(batch.success_count() as u64);
            self.metrics.observe_tx_gas_used(batch.gas_used);

            if let Some(submitted) = batch.timing.submitted_at {
                let confirmation_time = batch.timing.finalized_at.duration_since(submitted);
                self.metrics
                    .observe_tx_confirmation_time(confirmation_time.as_secs_f64());
            }
        }

        // Update pool lifecycle state for all operations
        // The pool's StatusBatcherHooks will automatically update request status
        let tx_hash_str = batch
            .tx_hash
            .map(|h| format!("{:?}", h))
            .unwrap_or_default();

        let mut included_ops: Vec<uuid::Uuid> = Vec::new();
        let mut failed_ops: Vec<(uuid::Uuid, String)> = Vec::new();

        for (id, status) in &batch.statuses {
            match status {
                OpStatus::Finalized { .. } => {
                    included_ops.push(*id);
                }
                OpStatus::Failed { reason } => {
                    self.metrics.inc_ops_failed(categorize_failure(reason));
                    failed_ops.push((*id, reason.to_string()));
                }
                OpStatus::Evicted { reason } => {
                    self.metrics.inc_ops_evicted(&format!("{:?}", reason));
                    failed_ops.push((*id, format!("Evicted: {}", reason)));
                }
            }
        }

        // Update pool lifecycle - hooks will push status updates to StatusBatcher
        if !included_ops.is_empty() {
            self.pool.mark_included(&included_ops, &tx_hash_str).await;
        }

        for (op_id, reason) in failed_ops {
            self.pool
                .mark_failed(op_id, crate::batcher::pool::LifecycleStage::Batched, reason)
                .await;
        }
    }

    /// Update metrics
    async fn update_metrics(&self) {
        let pool_len = self.pool.len().await;
        self.metrics.set_queue_depth(pool_len);
    }
}

/// Pre-flight check errors
#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error("nonce too low: expected {expected}, got {got}")]
    NonceTooLow { expected: U256, got: U256 },

    #[error("nonce too high: expected {expected}, got {got}")]
    NonceTooHigh { expected: U256, got: U256 },

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Categorize failure reason for metrics
fn categorize_failure(reason: &FailureReason) -> &'static str {
    match reason {
        FailureReason::SimulationReverted { .. } => "simulation",
        FailureReason::ExecutionReverted { .. } => "execution",
        FailureReason::NonceTooLow { .. } => "nonce_low",
        FailureReason::NonceTooHigh { .. } => "nonce_high",
        FailureReason::InsufficientBalance => "balance",
        FailureReason::InvalidSignature(_) => "signature",
        FailureReason::ValidationFailed(_) => "validation",
        FailureReason::ContractError { .. } => "contract",
        FailureReason::Unknown(_) => "unknown",
    }
}

/// Map failure reason to error code
fn error_code_for_failure(reason: &FailureReason) -> GatewayErrorCode {
    match reason {
        FailureReason::InvalidSignature(_) | FailureReason::ValidationFailed(_) => {
            GatewayErrorCode::BadRequest
        }
        _ => GatewayErrorCode::TransactionReverted,
    }
}

/// Builder for OpsBatcher
pub struct OpsBatcherBuilder<Prov, WS, Policy: OrderingPolicy<T = OpEnvelopeInner>> {
    provider: Arc<Prov>,
    ws_provider: Option<Arc<WS>>,
    tracker: Arc<RequestTracker>,
    config: OpsBatcherConfig,
    metrics: Option<OpsBatcherMetrics>,
    _policy: std::marker::PhantomData<Policy>,
}

impl<
        Prov: Provider + Clone + Send + Sync + 'static,
        WS: Provider + PubSubConnect + Clone + Send + Sync + 'static,
        Policy: OrderingPolicy<T = OpEnvelopeInner>,
    > OpsBatcherBuilder<Prov, WS, Policy>
{
    /// Create a new builder with the required components.
    ///
    /// The registry is needed to create the PendingBatchConfig.
    pub fn new(
        provider: Arc<Prov>,
        ws_provider: Option<Arc<WS>>,
        tracker: Arc<RequestTracker>,
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    ) -> Self {
        Self {
            provider,
            ws_provider,
            tracker,
            config: OpsBatcherConfig::new(registry),
            metrics: None,
            _policy: std::marker::PhantomData,
        }
    }

    pub fn with_config(mut self, config: OpsBatcherConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_metrics(mut self, metrics: OpsBatcherMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Build the OpsBatcher, returning the batcher, handle, and shutdown signal.
    ///
    /// The returned `IngressController` provides backpressure-aware submission
    /// methods (`try_submit` and `submit_with_backpressure`).
    pub fn build(self) -> (OpsBatcher<Prov, WS, Policy>, IngressController, Signal) {
        let metrics = self.metrics.unwrap_or_else(OpsBatcherMetrics::new);
        OpsBatcher::new(
            self.provider,
            self.ws_provider,
            self.tracker,
            self.config,
            metrics,
        )
    }
}
