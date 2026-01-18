//! # Pending Batch State Machine
//!
//! This module implements a typestate-based batch processing pipeline for World ID operations.
//! The design uses Rust's type system to enforce correct state transitions at compile time.
//!
//! ## Architecture
//!
//! The batch lifecycle is modeled as a state machine with three phases:
//!
//! ```text
//! ┌─────────┐     ┌──────────┐     ┌───────────┐
//! │ Pending │ ──► │ Batching │ ──► │ Finalized │
//! └─────────┘     └──────────┘     └───────────┘
//! ```
//!
//! ### Pending Phase
//! - Collects incoming operations from an `mpsc` channel
//! - Tracks gas budget and evicts operations that exceed limits
//! - Transitions when the channel closes or timeout is reached
//!
//! ### Batching Phase
//! - Builds a Multicall3 transaction with `allowFailure=true`
//! - Submits to the blockchain and waits for confirmation
//! - Parses individual operation results from the multicall response
//!
//! ### Finalized Phase
//! - Terminal state containing the final batch result
//! - Includes transaction hash, gas used, and per-operation statuses
//!
//! ## Usage
//!
//! ```rust,ignore
//! use pending_batch::{PendingBatch, BatchDriver, PendingBatchConfig};
//! use futures::StreamExt;
//!
//! // Initialize the batch with provider and config
//! let (batch, op_sender) = PendingBatch::init(provider, config, None);
//!
//! // Submit operations through the sender
//! op_sender.send(op1).await?;
//! op_sender.send(op2).await?;
//! drop(op_sender); // Signal end of operations
//!
//! // Drive the batch through all phases
//! let mut driver = BatchDriver::new(batch);
//! while let Some(yield_item) = driver.next().await {
//!     match yield_item {
//!         BatchYield::PhaseComplete { completed, next } => {
//!             println!("Completed {} -> {}", completed, next);
//!         }
//!         BatchYield::Done(result) => {
//!             println!("Batch finalized: {:?}", result.tx_hash);
//!         }
//!     }
//! }
//! ```
//!
//! ## Design Decisions
//!
//! - **Typestate pattern**: Prevents invalid state transitions at compile time
//! - **allowFailure=true**: Individual operation failures don't fail the entire batch
//! - **Gas budgeting**: Operations exceeding the gas limit are evicted, not rejected
//! - **Cancellation support**: Uses `CancellationToken` for graceful shutdown

use crate::batcher::metrics::BatchMetricsRecorder;
use crate::batcher::pending_batch::private::State;
use crate::batcher::types::{
    EvictionReason, FailureReason, FinalizedBatch, OpEnvelopeInner, OpStatus, Operation,
};

use alloy::network::ReceiptResponse;
use alloy::primitives::{address, Address, Bytes, B256};
use alloy::providers::DynProvider;
use alloy::sol;
use futures::Stream;
use std::any::TypeId;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

pub const MULTICALL3_ADDR: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 {
            address target;
            bool allowFailure;
            bytes callData;
        }

        struct Result {
            bool success;
            bytes returnData;
        }

        function aggregate3(Call3[] calldata calls) external payable returns (Result[] memory returnData);
    }
}

/// Configuration for batch processing behavior.
///
/// Controls timing, gas limits, fee escalation, and transaction retry behavior.
/// All durations and limits can be customized for different network conditions.
///
/// # Example
///
/// ```rust,ignore
/// let config = PendingBatchConfig::new(registry)
///     .with_max_gas(20_000_000);
/// ```
#[derive(Clone)]
pub struct PendingBatchConfig {
    /// How long to wait before resubmitting a pending transaction with higher fees.
    pub resubmit_timeout: Duration,
    /// Maximum fee multiplier relative to initial estimate (safety cap).
    pub max_fee_multiplier: f64,
    /// Fee multiplier increase per resubmission attempt (e.g., 1.1 = 10% increase).
    pub fee_escalation_step: f64,
    /// Maximum number of transaction resubmission attempts.
    pub max_resubmissions: u32,
    /// Timeout for simulation calls.
    pub simulation_timeout: Duration,
    /// Registry contract instance for building operation calldata.
    pub registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    /// Debounce interval for batching simulation requests.
    pub simulation_debounce: Duration,
    /// Maximum time to stay in pending phase collecting operations.
    pub max_pending_duration: Duration,
    /// Base delay between retry attempts (may be multiplied for backoff).
    pub retry_base_delay: Duration,
    /// Maximum gas budget per batch. Operations exceeding this limit are evicted.
    pub max_gas: u64,
}

impl PendingBatchConfig {
    pub fn new(registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>) -> Self {
        Self {
            resubmit_timeout: Duration::from_secs(30),
            max_fee_multiplier: 2.0,
            fee_escalation_step: 1.1,
            max_resubmissions: 5,
            simulation_timeout: Duration::from_secs(10),
            registry,
            simulation_debounce: Duration::from_millis(100),
            max_pending_duration: Duration::from_secs(300),
            retry_base_delay: Duration::from_secs(1),
            max_gas: 15_000_000,
        }
    }

    pub fn with_max_gas(mut self, max_gas: u64) -> Self {
        self.max_gas = max_gas;
        self
    }
}

/// A typestate-driven future that processes a batch through its lifecycle phases.
///
/// `PendingBatchFuture<S>` represents a batch in state `S`. The type parameter ensures
/// that only valid state transitions can occur at compile time:
///
/// - `PendingBatchFuture<Pending>` - Collecting operations from the channel
/// - `PendingBatchFuture<Batching>` - Submitting and confirming transaction
/// - `PendingBatchFuture<Finalized>` - Terminal state with final result
///
/// # Driving the State Machine
///
/// Use [`BatchDriver`] to drive the batch through all phases as a Stream,
/// or manually call `execute_phase` on each state.
///
/// # Cancellation
///
/// The batch respects the `CancellationToken` passed during construction.
/// When cancelled, all pending operations are marked as evicted.
pub type PendingBatchFut<S> = PendingBatchFuture<S>;

/// A future that drives the batch state machine through phases.
#[must_use = "futures do nothing unless polled"]
struct PendingBatchFuture<S: State> {
    pub batch_id: Uuid,
    pub provider: Arc<DynProvider>,
    pub metrics: Option<BatchMetricsRecorder>,
    pub cancel: CancellationToken,
    pub created_at: Instant,
    pub ctx: BatchContext<S>,
    pub _marker: PhantomData<S>,
}

impl<S: State> Unpin for PendingBatchFuture<S> {}

impl<S: State> PendingBatchFuture<S> {
    /// Get the batch ID.
    pub fn batch_id(&self) -> Uuid {
        self.batch_id
    }

    /// Get a reference to the current context.
    pub fn context(&self) -> &BatchContext<S> {
        &self.ctx
    }

    /// Get a mutable reference to the context.
    pub fn context_mut(&mut self) -> &mut BatchContext<S> {
        &mut self.ctx
    }

    /// Get the current state type ID.
    pub fn current(&self) -> TypeId {
        TypeId::of::<S>()
    }

    /// Get metrics recorder if available.
    pub fn metrics(&self) -> Option<&BatchMetricsRecorder> {
        self.metrics.as_ref()
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Transform into the next state.
    pub fn next(self) -> PendingBatchFuture<S::Next> {
        PendingBatchFuture {
            batch_id: self.batch_id,
            provider: self.provider,
            metrics: self.metrics,
            cancel: self.cancel,
            created_at: self.created_at,
            ctx: self.ctx.next(),
            _marker: PhantomData,
        }
    }
}

/// State marker for the pending phase (collecting operations).
///
/// In this phase, the batch receives operations through an `mpsc` channel.
/// The phase completes when the channel closes or the timeout is reached.
pub type Pending = private::Pending;

/// State marker for the batching phase (transaction submission).
///
/// In this phase, the batch builds a Multicall3 transaction and submits it
/// to the blockchain, waiting for confirmation.
pub type Batching = private::Batching;

/// State marker for the finalized phase (terminal).
///
/// This is the terminal state. Call `into_result()` to extract the
/// [`FinalizedBatch`] containing transaction results and operation statuses.
pub type Finalized = private::Finalized;

mod private {
    use std::{
        any::TypeId,
        collections::HashMap,
        future::Future,
        marker::PhantomData,
        sync::Arc,
        time::{Duration, Instant},
    };

    use alloy::{network::ReceiptResponse, primitives::B256, providers::DynProvider};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::batcher::{
        BatchMetricsRecorder, BatchTiming, EvictionReason, FinalizedBatch, OpEnvelopeInner, OpStatus, pending_batch::{
            BatchContext, ConfirmationResult, PendingBatchConfig, PendingBatchFuture, build_calldata, mark_all_cancelled, mark_all_failed, parse_multicall_results
        }
    };

    pub trait State: Clone + Default + Send + Sync + 'static {
        type Next: State + Sized;

        /// Human-readable name for this phase.
        fn name(&self) -> &'static str;

        /// Whether this is a terminal state.
        fn is_terminal(&self) -> bool {
            false
        }

        /// Called when entering this state (for metrics/telemetry).
        fn on_enter(batch: &PendingBatchFuture<Self>)
        where
            Self: Sized;

        /// Called when exiting this state (for metrics/telemetry).
        fn on_exit(batch: &PendingBatchFuture<Self::Next>)
        where
            Self: Sized;

        fn execute_phase(
            self,
            batch: PendingBatchFuture<Self>,
        ) -> std::pin::Pin<Box<dyn Future<Output = PendingBatchFuture<Self::Next>> + Send>>;
    }

    /// Pending state - collecting and simulating operations.
    #[derive(Default, Clone)]
    pub struct Pending;

    /// Batching state - submitting and confirming transaction.
    #[derive(Default, Clone)]
    pub struct Batching;

    #[derive(Default, Clone)]
    /// Finalized state - terminal.
    pub struct Finalized;

    impl State for Pending {
        type Next = Batching;

        fn name(&self) -> &'static str {
            "pending"
        }

        fn is_terminal(&self) -> bool {
            false
        }

        fn on_enter(_batch: &PendingBatchFuture<Self>) {
            tracing::debug!(state = "pending", "Entering state");
        }

        fn on_exit(_batch: &PendingBatchFuture<Self::Next>) {
            tracing::debug!(state = "pending", "Exiting state");
        }

        fn execute_phase(
            self,
            batch: PendingBatchFuture<Self>,
        ) -> std::pin::Pin<Box<dyn Future<Output = PendingBatchFuture<Self::Next>> + Send>>
        {
            Box::pin(self.execute_pending_phase(batch))
        }
    }

    impl State for Batching {
        type Next = Finalized;

        fn name(&self) -> &'static str {
            "batching"
        }

        fn is_terminal(&self) -> bool {
            false
        }

        fn on_enter(_batch: &PendingBatchFuture<Self>) {
            tracing::debug!(state = "batching", "Entering state");
        }

        fn on_exit(_batch: &PendingBatchFuture<Self::Next>) {
            tracing::debug!(state = "batching", "Exiting state");
        }

        fn execute_phase(
            self,
            batch: PendingBatchFuture<Self>,
        ) -> std::pin::Pin<Box<dyn Future<Output = PendingBatchFuture<Self::Next>> + Send>>
        {
            Box::pin(self.execute_batching_phase(batch))
        }
    }

    impl State for Finalized {
        type Next = Finalized;

        fn name(&self) -> &'static str {
            "finalized"
        }

        fn is_terminal(&self) -> bool {
            true
        }

        fn on_enter(_batch: &PendingBatchFuture<Self>) {
            tracing::debug!(state = "finalized", "Entering state");
        }

        fn on_exit(_batch: &PendingBatchFuture<Self::Next>) {
            tracing::debug!(state = "finalized", "Exiting state");
        }

        fn execute_phase(
            self,
            batch: PendingBatchFuture<Self>,
        ) -> std::pin::Pin<Box<dyn Future<Output = PendingBatchFuture<Self::Next>> + Send>>
        {
            // Terminal state - just return the batch unchanged
            Box::pin(async move { batch.next() })
        }
    }

    impl<S: State> BatchContext<S> {
        /// Transform context to the next state type.
        /// Safe because PhantomData<S> is zero-sized.
        pub fn next<N: State>(self) -> BatchContext<N> {
            BatchContext {
                ops: self.ops,
                statuses: self.statuses,
                result: self.result,
                op_rx: self.op_rx,
                config: self.config,
                max_gas: self.max_gas,
                current_gas: self.current_gas,
                _marker: PhantomData,
            }
        }
    }

    impl BatchContext<Pending> {
        pub fn new(
            op_rx: mpsc::Receiver<OpEnvelopeInner>,
            config: Arc<PendingBatchConfig>,
        ) -> Self {
            let max_gas = config.max_gas;

            Self {
                ops: Vec::new(),
                statuses: HashMap::new(),
                result: None,
                op_rx: Some(op_rx),
                config,
                max_gas,
                current_gas: 0,
                _marker: PhantomData,
            }
        }

        /// Try to add an operation, respecting gas limits.
        /// Returns true if added, false if would exceed gas limit.
        fn try_add_op(&mut self, op: OpEnvelopeInner) -> bool {
            let op_gas = op.op.estimated_gas();
            if self.current_gas + op_gas <= self.max_gas {
                self.current_gas += op_gas;
                self.ops.push(op);
                true
            } else {
                // Evict due to gas limit
                self.statuses.insert(
                    op.id,
                    OpStatus::Evicted {
                        reason: EvictionReason::BatchFull,
                    },
                );
                false
            }
        }
    }

    // ============================================================================
    // State Execution Logic
    // ============================================================================

    impl Pending {
        /// Execute the pending phase - collect operations from the channel.
        async fn execute_pending_phase(
            self,
            mut batch: PendingBatchFuture<Self>,
        ) -> PendingBatchFuture<<Self as State>::Next> {
            let batch_id = batch.batch_id;
            let cancel = batch.cancel.clone();
            let config = batch.ctx.config.clone();

            // Take the receiver from context
            let mut op_rx = batch
                .ctx
                .op_rx
                .take()
                .expect("Pending phase requires op_rx");

            let pending_deadline = Instant::now() + config.max_pending_duration;

            tracing::info!(batch_id = %batch_id, "Executing pending phase");

            loop {
                let pending_timeout = pending_deadline.saturating_duration_since(Instant::now());

                tokio::select! {
                    biased;

                    _ = cancel.cancelled() => {
                        tracing::info!(batch_id = %batch_id, "Cancelled");
                        mark_all_cancelled(&mut batch.ctx.statuses, &batch.ctx.ops);
                        batch.ctx.ops.clear();
                        break;
                    }

                    maybe_op = op_rx.recv() => {
                        match maybe_op {
                            Some(op) => {
                                tracing::debug!(batch_id = %batch_id, op_id = %op.id, "Received op");
                                // TODO: Track simulation needs when implemented
                                let _ = batch.ctx.try_add_op(op);
                            }
                            None => {
                                tracing::info!(batch_id = %batch_id, ops = batch.ctx.ops.len(), "Channel closed");
                                // TODO: Run final simulation if needed
                                break;
                            }
                        }
                    }

                    _ = tokio::time::sleep(pending_timeout) => {
                        tracing::warn!(batch_id = %batch_id, "Pending timeout");
                        break;
                    }
                }
            }

            tracing::info!(
                batch_id = %batch_id,
                ops = batch.ctx.ops.len(),
                evicted = batch.ctx.statuses.len(),
                "Pending phase complete"
            );

            batch.next()
        }
    }

    impl Batching {
        /// Execute the batching phase - submit and confirm transaction.
        async fn execute_batching_phase(
            self,
            mut batch: PendingBatchFuture<Self>,
        ) -> PendingBatchFuture<<Self as State>::Next> {
            let batch_id = batch.batch_id;
            let cancel = batch.cancel.clone();
            let config = batch.ctx.config.clone();
            let created_at = batch.created_at;

            tracing::info!(batch_id = %batch_id, ops = batch.ctx.ops.len(), "Executing batching phase");

            // Empty batch - finalize immediately
            if batch.ctx.ops.is_empty() {
                batch.ctx.result = Some(build_finalized(
                    batch_id,
                    &[],
                    std::mem::take(&mut batch.ctx.statuses),
                    None,
                    created_at,
                ));
                return batch.next();
            }

            let attempt = 0u32;

            if cancel.is_cancelled() {
                mark_all_failed(&mut batch.ctx.statuses, &batch.ctx.ops, "Cancelled");
                batch.ctx.result = Some(build_finalized(
                    batch_id,
                    &[],
                    std::mem::take(&mut batch.ctx.statuses),
                    None,
                    created_at,
                ));
                return batch.next();
            }

            let fee_mult = config.fee_escalation_step.powi(attempt as i32);
            tracing::info!(batch_id = %batch_id, attempt = attempt + 1, fee_mult = %fee_mult, "Submitting batch");

            if let Some(ref m) = batch.metrics {
                if attempt == 0 {
                    m.record_submission();
                } else {
                    m.record_resubmission();
                }
            }

            // Build multicall3 calls with allowFailure = true
            let registry = &config.registry;
            let registry_addr = *registry.address();
            let mut calls: Vec<super::Multicall3::Call3> = Vec::with_capacity(batch.ctx.ops.len());

            for op in &batch.ctx.ops {
                if let Some(calldata) = build_calldata(registry, &op.op) {
                    calls.push(super::Multicall3::Call3 {
                        target: registry_addr,
                        allowFailure: true, // Allow individual failures
                        callData: calldata,
                    });
                }
            }

            if calls.is_empty() {
                batch.ctx.result = Some(build_finalized(
                    batch_id,
                    &[],
                    std::mem::take(&mut batch.ctx.statuses),
                    None,
                    created_at,
                ));
                return batch.next();
            }

            // Submit multicall transaction
            let mc = super::Multicall3::new(super::MULTICALL3_ADDR, batch.provider.clone());
            match mc.aggregate3(calls).send().await {
                Ok(builder) => {
                    let tx_hash = *builder.tx_hash();
                    tracing::info!(batch_id = %batch_id, tx_hash = ?tx_hash, "Batch submitted");

                    // Wait for receipt
                    match builder.get_receipt().await {
                        Ok(receipt) => {
                            let block_num = receipt.block_number();
                            let gas_used = receipt.gas_used();

                            // Parse individual op results
                            let op_results = parse_multicall_results(&receipt, batch.ctx.ops.len());

                            tracing::info!(
                                batch_id = %batch_id,
                                tx_hash = ?tx_hash,
                                success_count = op_results.iter().filter(|r| r.success).count(),
                                fail_count = op_results.iter().filter(|r| !r.success).count(),
                                "Batch confirmed"
                            );

                            let confirmation = ConfirmationResult {
                                tx_hash,
                                block_number: block_num.unwrap_or(0),
                                gas_used,
                                op_results,
                            };

                            batch.ctx.result = Some(build_finalized(
                                batch_id,
                                &batch.ctx.ops,
                                std::mem::take(&mut batch.ctx.statuses),
                                Some(confirmation),
                                created_at,
                            ));
                        }
                        Err(e) => {
                            tracing::error!(batch_id = %batch_id, error = %e, "Batch confirmation failed");
                            mark_all_failed(
                                &mut batch.ctx.statuses,
                                &batch.ctx.ops,
                                &format!("confirmation error: {}", e),
                            );
                            batch.ctx.result = Some(build_finalized(
                                batch_id,
                                &[],
                                std::mem::take(&mut batch.ctx.statuses),
                                None,
                                created_at,
                            ));
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(batch_id = %batch_id, error = %e, "Multicall send failed");
                    mark_all_failed(
                        &mut batch.ctx.statuses,
                        &batch.ctx.ops,
                        &format!("send error: {}", e),
                    );
                    batch.ctx.result = Some(build_finalized(
                        batch_id,
                        &[],
                        std::mem::take(&mut batch.ctx.statuses),
                        None,
                        created_at,
                    ));
                }
            }

            batch.next()
        }
    }

    fn build_finalized(
        batch_id: Uuid,
        ops: &[OpEnvelopeInner],
        mut statuses: HashMap<Uuid, OpStatus>,
        result: Option<ConfirmationResult>,
        created_at: Instant,
    ) -> FinalizedBatch {
        let confirmation = result.unwrap_or_else(|| ConfirmationResult {
            tx_hash: B256::ZERO,
            block_number: 0,
            gas_used: 0,
            op_results: vec![],
        });

        // Populate statuses for all processed ops based on multicall results
        for (i, op) in ops.iter().enumerate() {
            let op_result = confirmation.op_results.get(i);
            let status = match op_result {
                Some(r) if r.success => OpStatus::Finalized {
                    tx_hash: confirmation.tx_hash,
                    block_number: confirmation.block_number,
                    gas_used: confirmation.gas_used / ops.len().max(1) as u64, // Approximate per-op gas
                },
                Some(_) => OpStatus::Failed {
                    reason: super::FailureReason::ExecutionReverted {
                        message: "multicall call failed".into(),
                        revert_data: None,
                    },
                },
                None => {
                    // No result means we didn't submit (empty batch or error)
                    // Don't overwrite if already has a status (e.g. evicted)
                    continue;
                }
            };
            // Only set status if not already set (evicted ops keep their eviction status)
            statuses.entry(op.id).or_insert(status);
        }

        FinalizedBatch {
            batch_id,
            timing: BatchTiming {
                created_at: created_at.into(),
                simulation_completed_at: None,
                resubmission_count: 0,
                submitted_at: None,
                finalized_at: Instant::now().into(),
                total_duration: Duration::ZERO,
            },
            statuses,
            tx_hash: Some(confirmation.tx_hash),
            block_number: Some(confirmation.block_number),
            gas_used: confirmation.gas_used,
        }
    }

    impl PendingBatchFuture<Finalized> {
        /// Extract the final result from the batch.
        pub fn into_result(self) -> FinalizedBatch {
            self.ctx
                .result
                .expect("Finalized batch should have a result")
        }
    }
}

/// A stream that drives the batch through all phases and yields progress.
///
/// `BatchDriver` wraps a `PendingBatchFuture<Pending>` and implements `Stream`,
/// yielding `BatchYield` items as each phase completes. This provides a convenient
/// way to drive the state machine without manually handling state transitions.
///
/// # Example
///
/// ```rust,ignore
/// use futures::StreamExt;
///
/// let (batch, sender) = PendingBatch::init(provider, config, None);
/// drop(sender); // No operations
///
/// let mut driver = BatchDriver::new(batch);
/// while let Some(item) = driver.next().await {
///     match item {
///         BatchYield::PhaseComplete { completed, next } => {
///             println!("{} -> {}", completed, next);
///         }
///         BatchYield::Done(result) => {
///             println!("Finalized with tx: {:?}", result.tx_hash);
///         }
///     }
/// }
/// ```
///
/// # Phases
///
/// The driver yields:
/// 1. `PhaseComplete { completed: "pending", next: "batching" }` after pending phase
/// 2. `Done(FinalizedBatch)` when the batch is finalized
pub struct BatchDriver {
    state: DriverState,
    pending_future: Option<Pin<Box<dyn Future<Output = PendingBatchFuture<Batching>> + Send>>>,
    batching_future: Option<Pin<Box<dyn Future<Output = PendingBatchFuture<Finalized>> + Send>>>,
}

enum DriverState {
    Pending(Option<PendingBatchFuture<Pending>>),
    Batching(Option<PendingBatchFuture<Batching>>),
    Finalized(PendingBatchFuture<Finalized>),
    Done,
}

impl BatchDriver {
    /// Create a new driver from a pending batch.
    pub fn new(batch: PendingBatchFuture<Pending>) -> Self {
        Self {
            state: DriverState::Pending(Some(batch)),
            pending_future: None,
            batching_future: None,
        }
    }
}

impl Stream for BatchDriver {
    type Item = BatchYield;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                DriverState::Pending(batch_opt) => {
                    // If we don't have a future yet, create one
                    if this.pending_future.is_none() {
                        if let Some(batch) = batch_opt.take() {
                            let fut = Pending::default().execute_phase(batch);
                            this.pending_future = Some(Box::pin(fut));
                        } else {
                            // No batch and no future means we're done
                            this.state = DriverState::Done;
                            return Poll::Ready(None);
                        }
                    }

                    // Poll the future
                    if let Some(fut) = &mut this.pending_future {
                        match fut.as_mut().poll(cx) {
                            Poll::Ready(next_batch) => {
                                this.pending_future = None;
                                this.state = DriverState::Batching(Some(next_batch));
                                return Poll::Ready(Some(BatchYield::PhaseComplete {
                                    completed: "pending",
                                    next: "batching",
                                }));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }

                DriverState::Batching(batch_opt) => {
                    // If we don't have a future yet, create one
                    if this.batching_future.is_none() {
                        if let Some(batch) = batch_opt.take() {
                            let fut = Batching::default().execute_phase(batch);
                            this.batching_future = Some(Box::pin(fut));
                        } else {
                            this.state = DriverState::Done;
                            return Poll::Ready(None);
                        }
                    }

                    // Poll the future
                    if let Some(fut) = &mut this.batching_future {
                        match fut.as_mut().poll(cx) {
                            Poll::Ready(next_batch) => {
                                this.batching_future = None;
                                let result = next_batch.into_result();
                                this.state = DriverState::Done;
                                return Poll::Ready(Some(BatchYield::Done(result)));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }

                DriverState::Finalized(batch) => {
                    let result = std::mem::replace(&mut this.state, DriverState::Done);
                    if let DriverState::Finalized(b) = result {
                        return Poll::Ready(Some(BatchYield::Done(b.into_result())));
                    }
                }

                DriverState::Done => {
                    return Poll::Ready(None);
                }
            }
        }
    }
}

/// Factory for creating `PendingBatchFuture` instances.
///
/// Provides initialization methods for starting new batch processing pipelines.
/// The factory pattern separates configuration from the stateful batch future.
///
/// # Example
///
/// ```rust,ignore
/// // Simple initialization
/// let (batch, sender) = PendingBatch::init(provider, config, Some(metrics));
///
/// // With custom cancellation
/// let cancel = CancellationToken::new();
/// let (batch, sender) = PendingBatch::with_cancellation(provider, config, None, cancel.clone());
/// ```
pub struct PendingBatch;

impl PendingBatch {
    /// Initialize a new pending batch with a DynProvider.
    ///
    /// Returns the batch future and a sender for submitting operations.
    /// Drop the sender once all operations are submitted to trigger
    /// the transition from Pending to Batching.
    pub fn init(
        provider: Arc<DynProvider>,
        config: PendingBatchConfig,
        metrics: Option<BatchMetricsRecorder>,
    ) -> (PendingBatchFuture<Pending>, mpsc::Sender<OpEnvelopeInner>) {
        Self::with_cancellation(provider, config, metrics, CancellationToken::new())
    }

    /// Initialize with a custom cancellation token.
    pub fn with_cancellation(
        provider: Arc<DynProvider>,
        config: PendingBatchConfig,
        metrics: Option<BatchMetricsRecorder>,
        cancel: CancellationToken,
    ) -> (PendingBatchFuture<Pending>, mpsc::Sender<OpEnvelopeInner>) {
        let batch_id = Uuid::new_v4();
        let (op_tx, op_rx) = mpsc::channel(1024);
        let created_at = Instant::now();
        let config = Arc::new(config);

        let ctx = BatchContext::<Pending>::new(op_rx, config.clone());

        let batch_fut = PendingBatchFuture {
            batch_id,
            provider,
            metrics,
            cancel,
            created_at,
            ctx,
            _marker: PhantomData,
        };

        (batch_fut, op_tx)
    }
}

/// Progress updates yielded by [`BatchDriver`] during batch processing.
///
/// The driver yields these items as the batch transitions through phases,
/// allowing callers to track progress or perform intermediate actions.
///
/// # Variants
///
/// - `PhaseComplete`: A phase finished, moving to the next
/// - `Done`: The batch reached its terminal state with a final result
#[derive(Debug)]
pub enum BatchYield {
    /// A phase completed successfully, transitioning to the next.
    ///
    /// Fields contain the names of the completed and next phases for logging/metrics.
    PhaseComplete {
        /// Name of the phase that just completed (e.g., "pending").
        completed: &'static str,
        /// Name of the phase now beginning (e.g., "batching").
        next: &'static str,
    },
    /// The batch has finalized and processing is complete.
    ///
    /// Contains the final [`FinalizedBatch`] with transaction results and operation statuses.
    Done(FinalizedBatch),
}

// ============================================================================
// Shared Context
// ============================================================================

/// Shared context that flows through all batch states.
///
/// `BatchContext<S>` holds all the data needed during batch processing:
/// - Collected operations and their statuses
/// - Gas tracking for batch limits
/// - Configuration and the final result
///
/// The `S` type parameter corresponds to the batch's current state, ensuring
/// the context is only accessed in type-safe ways for each phase.
///
/// # Gas Management
///
/// Operations are added via `try_add_op()`, which checks the gas budget.
/// If an operation would exceed `max_gas`, it is evicted with
/// `EvictionReason::BatchFull` rather than rejected.
pub struct BatchContext<S: State> {
    /// Collected operations.
    ops: Vec<OpEnvelopeInner>,
    /// Evicted/failed operation statuses.
    statuses: HashMap<Uuid, OpStatus>,
    /// Final result (set in finalized state).
    result: Option<FinalizedBatch>,
    /// Receiver for incoming operations (consumed during Pending phase).
    op_rx: Option<mpsc::Receiver<OpEnvelopeInner>>,
    /// Configuration.
    config: Arc<PendingBatchConfig>,
    /// Maximum gas budget for this batch.
    max_gas: u64,
    /// Current accumulated gas.
    current_gas: u64,
    /// Marker for current state.
    _marker: PhantomData<S>,
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

/// Result of an individual operation within a multicall batch.
///
/// When using Multicall3 with `allowFailure=true`, each call in the batch
/// returns a success flag and return data. This struct captures that per-op result.
///
/// # Fields
///
/// - `success`: Whether this specific operation succeeded
/// - `return_data`: The raw return bytes (or revert data if failed)
#[derive(Debug, Clone)]
pub struct OpResult {
    /// Whether this operation succeeded in the multicall.
    pub success: bool,
    /// Raw return data from the call (empty on revert unless error data included).
    pub return_data: Bytes,
}

/// Internal type for tracking transaction confirmation results.
///
/// Captures both the on-chain transaction metadata and per-operation results
/// parsed from the multicall response.
struct ConfirmationResult {
    /// Hash of the confirmed transaction.
    tx_hash: B256,
    /// Block number where the transaction was included.
    block_number: u64,
    /// Total gas consumed by the transaction.
    gas_used: u64,
    /// Per-operation results from multicall parsing.
    op_results: Vec<OpResult>,
}

/// Mark all operations as cancelled due to batch cancellation.
///
/// Called when the batch's `CancellationToken` is triggered.
fn mark_all_cancelled(statuses: &mut HashMap<Uuid, OpStatus>, ops: &[OpEnvelopeInner]) {
    for op in ops {
        statuses.insert(
            op.id,
            OpStatus::Evicted {
                reason: EvictionReason::BatchCancelled,
            },
        );
    }
}

/// Mark all operations as failed with a given reason.
///
/// Called when the entire batch fails (e.g., transaction submission error).
fn mark_all_failed(statuses: &mut HashMap<Uuid, OpStatus>, ops: &[OpEnvelopeInner], reason: &str) {
    for op in ops {
        statuses.insert(
            op.id,
            OpStatus::Failed {
                reason: FailureReason::Unknown(reason.into()),
            },
        );
    }
}

/// Build calldata for a World ID registry operation.
///
/// Generates the ABI-encoded calldata for the given operation type by calling
/// the appropriate method on the registry contract instance.
///
/// # Returns
///
/// - `Some(Bytes)` with the encoded calldata for authenticator operations
/// - `None` for `CreateAccount` (handled by separate batcher)
pub fn build_calldata(
    registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
    op: &Operation,
) -> Option<Bytes> {
    match op {
        Operation::InsertAuthenticator(data) => Some(
            registry
                .insertAuthenticator(
                    data.leaf_index,
                    data.new_authenticator_address,
                    data.pubkey_id,
                    data.new_authenticator_pubkey,
                    data.old_commit,
                    data.new_commit,
                    data.signature.clone(),
                    data.sibling_nodes.clone(),
                    data.nonce,
                )
                .calldata()
                .clone(),
        ),
        Operation::UpdateAuthenticator(data) => Some(
            registry
                .updateAuthenticator(
                    data.leaf_index,
                    data.old_authenticator_address,
                    data.new_authenticator_address,
                    data.pubkey_id,
                    data.new_authenticator_pubkey,
                    data.old_commit,
                    data.new_commit,
                    data.signature.clone(),
                    data.sibling_nodes.clone(),
                    data.nonce,
                )
                .calldata()
                .clone(),
        ),
        Operation::RemoveAuthenticator(data) => Some(
            registry
                .removeAuthenticator(
                    data.leaf_index,
                    data.authenticator_address,
                    data.pubkey_id,
                    data.authenticator_pubkey,
                    data.old_commit,
                    data.new_commit,
                    data.signature.clone(),
                    data.sibling_nodes.clone(),
                    data.nonce,
                )
                .calldata()
                .clone(),
        ),
        Operation::RecoverAccount(data) => Some(
            registry
                .recoverAccount(
                    data.leaf_index,
                    data.new_authenticator_address,
                    data.new_authenticator_pubkey,
                    data.old_commit,
                    data.new_commit,
                    data.signature.clone(),
                    data.sibling_nodes.clone(),
                    data.nonce,
                )
                .calldata()
                .clone(),
        ),
        Operation::CreateAccount(_) => {
            // CreateAccount is handled by the separate CreateBatcher
            None
        }
    }
}

/// Parse multicall results from a transaction receipt.
///
/// When using Multicall3 with `allowFailure=true`, the aggregate3 function returns
/// a `Result[]` array containing the success/failure status of each call.
///
/// # Arguments
///
/// * `receipt` - The transaction receipt to parse
/// * `expected_count` - Number of operations in the batch (for result vector sizing)
///
/// # Returns
///
/// A vector of `OpResult` with one entry per operation. If the overall transaction
/// failed, all operations are marked as failed.
///
/// # TODO
///
/// Currently assumes success if the transaction succeeded. A full implementation
/// would decode the Multicall3::Result[] from the return data to get per-op status.
pub fn parse_multicall_results<R: ReceiptResponse>(
    receipt: &R,
    expected_count: usize,
) -> Vec<OpResult> {
    // The multicall3 aggregate3 function returns Result[] in the output
    // When the tx succeeds, we need to decode the return data to get individual results
    // For now, if the overall tx succeeded, we assume all ops succeeded
    // In a full implementation, you'd decode the return data from the call

    if receipt.status() {
        // Try to decode the multicall results from logs or output
        // For simplicity, assume success means all ops succeeded
        // TODO: Properly decode Multicall3::Result[] from return data
        (0..expected_count)
            .map(|_| OpResult {
                success: true,
                return_data: Bytes::new(),
            })
            .collect()
    } else {
        // Transaction failed entirely
        (0..expected_count)
            .map(|_| OpResult {
                success: false,
                return_data: Bytes::new(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::batcher::pending_batch::private::{Batching, Finalized, Pending};

    use super::*;

    #[test]
    fn test_state_names() {
        assert_eq!(Pending.name(), "pending");
        assert_eq!(Batching.name(), "batching");
        assert_eq!(Finalized.name(), "finalized");
    }
}
