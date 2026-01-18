//! Controller for permit-gated batch spawning and task utilities.
//!
//! This module provides:
//! - `Controller`: Manages concurrent batch execution with semaphore-based
//!   permit control. When permits are exhausted, batches are queued for deferred
//!   spawning.
//! - Task spawning utilities with panic handling and shutdown signals.

use crate::batcher::metrics::{BatchMetricsRecorder, OpsBatcherMetrics};
use crate::batcher::pending_batch::{BatchDriver, BatchYield, PendingBatch, PendingBatchConfig, PendingBatchFut};
use crate::batcher::status_batcher::StatusUpdate;
use crate::batcher::types::{FinalizedBatch, OpEnvelopeInner};
use crate::batcher::{Pending};
use alloy::providers::DynProvider;
use futures_util::{future::FusedFuture, future::Shared, FutureExt, StreamExt, TryFutureExt};
use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tracing::Instrument;
use uuid::Uuid;
use world_id_core::types::GatewayRequestState;

// ============================================================================
// Shutdown Signal
// ============================================================================

/// A cloneable Future that resolves when shutdown is signaled.
#[derive(Debug, Clone)]
pub struct Shutdown(Shared<oneshot::Receiver<()>>);

impl Future for Shutdown {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let pin = self.get_mut();
        if pin.0.is_terminated() || pin.0.poll_unpin(cx).is_ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Fires the shutdown signal when called or dropped.
#[derive(Debug)]
pub struct Signal(oneshot::Sender<()>);

impl Signal {
    /// Fire the signal manually.
    pub fn fire(self) {
        let _ = self.0.send(());
    }
}

/// Create a shutdown signal pair.
pub fn shutdown_signal() -> (Signal, Shutdown) {
    let (tx, rx) = oneshot::channel();
    (Signal(tx), Shutdown(rx.shared()))
}

// ============================================================================
// Panicked Task Error
// ============================================================================

/// Error containing information about a panicked task.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub struct PanickedTaskError {
    task_name: &'static str,
    error: Option<String>,
}

impl Display for PanickedTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(error) = &self.error {
            write!(
                f,
                "Critical task `{}` panicked: `{}`",
                self.task_name, error
            )
        } else {
            write!(f, "Critical task `{}` panicked", self.task_name)
        }
    }
}

impl PanickedTaskError {
    fn from_panic(task_name: &'static str, error: Box<dyn std::any::Any + Send>) -> Self {
        let error = match error.downcast::<String>() {
            Ok(value) => Some(*value),
            Err(error) => match error.downcast::<&str>() {
                Ok(value) => Some(value.to_string()),
                Err(_) => None,
            },
        };
        Self { task_name, error }
    }

    /// Get the task name.
    pub fn task_name(&self) -> &'static str {
        self.task_name
    }

    /// Get the error message if available.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

// ============================================================================
// Spawn Utilities
// ============================================================================

/// Spawn a critical task that notifies on panic.
///
/// If the task panics, a `PanickedTaskError` is sent to the channel.
/// The task is cancelled when shutdown is signaled.
pub fn spawn_critical<F>(
    name: &'static str,
    shutdown: Shutdown,
    panic_tx: mpsc::UnboundedSender<PanickedTaskError>,
    fut: F,
) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = std::panic::AssertUnwindSafe(fut)
        .catch_unwind()
        .map_err(move |error| {
            let task_error = PanickedTaskError::from_panic(name, error);
            tracing::error!("{task_error}");
            let _ = panic_tx.send(task_error);
        })
        .in_current_span();

    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = shutdown => {
                tracing::debug!(task = name, "task.shutdown");
            }
            result = task => {
                let _ = result; // Panic already handled
            }
        }
    })
}

/// Spawn a critical blocking task that notifies on panic.
pub fn spawn_critical_blocking<F>(
    name: &'static str,
    shutdown: Shutdown,
    panic_tx: mpsc::UnboundedSender<PanickedTaskError>,
    fut: F,
) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let handle = tokio::runtime::Handle::current();

    tokio::task::spawn_blocking(move || {
        handle.block_on(async move {
            let task = std::panic::AssertUnwindSafe(fut)
                .catch_unwind()
                .map_err(move |error| {
                    let task_error = PanickedTaskError::from_panic(name, error);
                    tracing::error!("{task_error}");
                    let _ = panic_tx.send(task_error);
                });

            tokio::select! {
                biased;
                _ = shutdown => {
                    tracing::debug!(task = name, "blocking_task.shutdown");
                }
                result = task => {
                    let _ = result;
                }
            }
        })
    })
}

/// Spawn a task with access to the shutdown signal.
pub fn spawn_with_signal<F, Fut>(shutdown: Shutdown, f: F) -> JoinHandle<()>
where
    F: FnOnce(Shutdown) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let fut = f(shutdown);
    tokio::spawn(fut.in_current_span())
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the controller.
#[derive(Clone)]
pub struct ControllerConfig {
    /// Maximum concurrent batches in flight.
    pub max_concurrent: usize,
    /// Pending batch configuration.
    pub pending_batch: PendingBatchConfig,
}

impl ControllerConfig {
    /// Create a new config with the required registry.
    pub fn new(registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>) -> Self {
        Self {
            max_concurrent: 3,
            pending_batch: PendingBatchConfig::new(registry),
        }
    }
}

// ============================================================================
// Ready Batch
// ============================================================================

/// A batch ready for spawning.
#[derive(Debug)]
pub struct ReadyBatch {
    /// Operations to include in the batch.
    pub ops: Vec<OpEnvelopeInner>,
    /// Gas budget for the batch.
    pub gas_budget: u64,
    /// When the batch was prepared.
    pub prepared_at: Instant,
}

impl ReadyBatch {
    pub fn new(ops: Vec<OpEnvelopeInner>, gas_budget: u64) -> Self {
        Self {
            ops,
            gas_budget,
            prepared_at: Instant::now(),
        }
    }

    pub fn size(&self) -> usize {
        self.ops.len()
    }
}

// ============================================================================
// Spawn Controller
// ============================================================================

/// Result from a batch task - either completed or shutdown.
#[derive(Debug)]
pub enum BatchResult {
    /// Batch completed successfully.
    Completed(FinalizedBatch),
    /// Batch was cancelled due to shutdown.
    Shutdown { batch_id: Uuid },
}

impl BatchResult {
    /// Returns the finalized batch if completed, None if shutdown.
    pub fn into_completed(self) -> Option<FinalizedBatch> {
        match self {
            Self::Completed(batch) => Some(batch),
            Self::Shutdown { .. } => None,
        }
    }

    /// Returns true if this is a completed batch.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Returns the batch ID regardless of result type.
    pub fn batch_id(&self) -> Option<Uuid> {
        match self {
            Self::Completed(batch) => Some(batch.batch_id),
            Self::Shutdown { batch_id } => Some(*batch_id),
        }
    }
}

/// Controller for permit-gated batch spawning.
///
/// This controller manages concurrent batch execution by:
/// 1. Acquiring semaphore permits before spawning
/// 2. Queuing batches when no permits are available
/// 3. Draining the queue when permits become available
/// 4. Respecting shutdown signals for graceful termination
///
/// Uses a `JoinSet` to track in-flight batches and await completions.
pub struct Controller {
    /// Semaphore for limiting concurrent batches.
    permits: Arc<Semaphore>,
    /// Maximum concurrent batches.
    max_concurrent: usize,
    /// Queue of batches waiting for permits.
    pending_spawns: VecDeque<ReadyBatch>,
    /// In-flight batch tasks.
    in_flight: JoinSet<BatchResult>,
    /// Sender for status updates.
    status_tx: mpsc::Sender<StatusUpdate>,
    /// Provider for batch execution.
    provider: Arc<DynProvider>,
    /// Pending batch configuration.
    batch_config: PendingBatchConfig,
    /// Metrics.
    metrics: OpsBatcherMetrics,
    /// Shutdown signal for graceful termination.
    shutdown: Shutdown,
    /// Panic channel for reporting critical failures.
    panic_tx: mpsc::UnboundedSender<PanickedTaskError>,
}

impl Controller {
    /// Create a new controller.
    pub fn new(
        provider: Arc<DynProvider>,
        config: ControllerConfig,
        status_tx: mpsc::Sender<StatusUpdate>,
        metrics: OpsBatcherMetrics,
        shutdown: Shutdown,
        panic_tx: mpsc::UnboundedSender<PanickedTaskError>,
    ) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(config.max_concurrent)),
            max_concurrent: config.max_concurrent,
            pending_spawns: VecDeque::new(),
            in_flight: JoinSet::new(),
            status_tx,
            provider,
            batch_config: config.pending_batch,
            metrics,
            shutdown,
            panic_tx,
        }
    }

    /// Try to spawn a batch, queuing it if no permits are available.
    ///
    /// This is a non-blocking operation. If permits are available, the batch
    /// is spawned immediately. Otherwise, it's added to the pending queue.
    ///
    /// # Returns
    /// * `true` if the batch was spawned immediately
    /// * `false` if the batch was queued
    pub fn try_spawn(&mut self, batch: ReadyBatch) -> bool {
        match self.permits.clone().try_acquire_owned() {
            Ok(permit) => {
                self.spawn_batch_task(batch, permit);
                true
            }
            Err(_) => {
                tracing::debug!(
                    pending = self.pending_spawns.len(),
                    "spawn_controller.queued_batch"
                );
                self.pending_spawns.push_back(batch);
                false
            }
        }
    }

    /// Poll for the next completed batch.
    ///
    /// Returns `None` if no batches are ready. This is non-blocking.
    /// After receiving a completion, call `drain_pending()` to spawn
    /// any queued batches.
    pub async fn next_completion(&mut self) -> Option<Result<BatchResult, tokio::task::JoinError>> {
        self.in_flight.join_next().await
    }

    /// Check if there are any in-flight batches.
    pub fn has_in_flight(&self) -> bool {
        !self.in_flight.is_empty()
    }

    /// Get number of in-flight batches.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Drain pending batches while permits are available.
    ///
    /// Call this after processing a batch completion to spawn queued batches.
    pub fn drain_pending(&mut self) {
        while let Some(batch) = self.pending_spawns.pop_front() {
            match self.permits.clone().try_acquire_owned() {
                Ok(permit) => {
                    tracing::debug!(
                        remaining = self.pending_spawns.len(),
                        "spawn_controller.drained_pending"
                    );
                    self.spawn_batch_task(batch, permit);
                }
                Err(_) => {
                    // No permits available, put batch back
                    self.pending_spawns.push_front(batch);
                    break;
                }
            }
        }
    }

    /// Spawn a batch task with the given permit.
    fn spawn_batch_task(&mut self, batch: ReadyBatch, permit: tokio::sync::OwnedSemaphorePermit) {
        let batch_size = batch.size();
        let gas_budget = batch.gas_budget;

        // Create metrics recorder
        let metrics_recorder = BatchMetricsRecorder::new(self.metrics.clone(), batch_size);

        // Create PendingBatch
        let (batch_fut, op_sender) = PendingBatch::init(
            self.provider.clone(),
            self.batch_config.clone(),
            Some(metrics_recorder),
        );

        let batch_id = batch_fut.batch_id();

        // Send status updates for batching state
        for op in &batch.ops {
            let _ = self.status_tx.try_send(StatusUpdate::new(
                op.id.to_string(),
                GatewayRequestState::Batching,
            ));
        }

        // Send operations to the batch
        for op in batch.ops {
            if op_sender.try_send(op).is_err() {
                tracing::warn!(batch_id = %batch_id, "spawn_controller.op_send_failed");
            }
        }

        // Drop sender to signal all operations sent
        drop(op_sender);

        tracing::info!(
            batch_id = %batch_id,
            size = batch_size,
            gas_budget = gas_budget,
            "spawn_controller.batch_spawned"
        );

        self.metrics.inc_batches_spawned();

        // Clone shutdown signal for this task
        let shutdown = self.shutdown.clone();
        let panic_tx = self.panic_tx.clone();

        // Spawn batch task into the JoinSet with panic handling
        self.in_flight.spawn(
            Self::drive_batch_with_shutdown(batch_id, batch_fut, permit, shutdown, panic_tx)
                .instrument(tracing::info_span!("batch", batch_id = %batch_id)),
        );
    }

    /// Drive a batch to completion with shutdown support and panic handling.
    ///
    /// The permit is held until the batch completes, then automatically dropped.
    /// If shutdown is signaled, the batch is cancelled and `BatchResult::Shutdown` is returned.
    async fn drive_batch_with_shutdown(
        batch_id: Uuid,
        batch_fut: PendingBatchFut<Pending>,
        _permit: tokio::sync::OwnedSemaphorePermit,
        shutdown: Shutdown,
        panic_tx: mpsc::UnboundedSender<PanickedTaskError>,
    ) -> BatchResult {
        // Wrap the actual work in catch_unwind for panic handling
        let task = std::panic::AssertUnwindSafe(Self::drive_batch_inner(batch_id, batch_fut))
            .catch_unwind()
            .map_err(move |error| {
                let task_error = PanickedTaskError::from_panic("batch_task", error);
                tracing::error!(batch_id = %batch_id, "{task_error}");
                let _ = panic_tx.send(task_error);
            });

        tokio::select! {
            biased;
            _ = shutdown => {
                tracing::debug!(batch_id = %batch_id, "batch.shutdown");
                BatchResult::Shutdown { batch_id }
            }
            result = task => {
                match result {
                    Ok(batch) => BatchResult::Completed(batch),
                    Err(()) => {
                        // Panic occurred, return a shutdown result
                        // The panic has already been reported via panic_tx
                        BatchResult::Shutdown { batch_id }
                    }
                }
            }
        }
        // Permit is dropped here when function returns
    }

    /// Inner batch driving logic (separated for panic handling).
    async fn drive_batch_inner(
        batch_id: Uuid,
        batch_fut: PendingBatchFut<Pending>,
    ) -> FinalizedBatch {
        use futures_util::StreamExt;

        let mut driver = BatchDriver::new(batch_fut);
        let mut result = None;

        while let Some(item) = driver.next().await {
            match item {
                BatchYield::PhaseComplete { completed, next } => {
                    tracing::debug!(
                        batch_id = %batch_id,
                        completed,
                        next,
                        "batch.phase_transition"
                    );
                }
                BatchYield::Done(batch) => {
                    result = Some(batch);
                }
            }
        }

        result.expect("Batch stream ended without Done")
    }

    /// Get the number of pending batches in the queue.
    pub fn pending_count(&self) -> usize {
        self.pending_spawns.len()
    }

    /// Get the number of available permits.
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Check if there are pending batches waiting.
    pub fn has_pending(&self) -> bool {
        !self.pending_spawns.is_empty()
    }

    /// Get the maximum concurrent batches.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Shutdown: drain all in-flight batches.
    ///
    /// Returns all batch results (both completed and shutdown).
    pub async fn drain_in_flight(&mut self) -> Vec<BatchResult> {
        let mut results = Vec::with_capacity(self.in_flight.len());
        while let Some(result) = self.in_flight.join_next().await {
            if let Ok(batch_result) = result {
                results.push(batch_result);
            }
        }
        results
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher::types::{CreateAccountOp, Operation};
    use alloy::primitives::{Address, Bytes, U256};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn mock_op() -> OpEnvelopeInner {
        OpEnvelopeInner {
            id: Uuid::new_v4(),
            op: Operation::CreateAccount(CreateAccountOp {
                initial_commitment: U256::from(1),
                signature: Bytes::from(vec![0u8; 65]),
            }),
            received_at: Instant::now().into(),
            signer: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    fn mock_ready_batch(size: usize) -> ReadyBatch {
        let ops: Vec<_> = (0..size).map(|_| mock_op()).collect();
        ReadyBatch::new(ops, 1_000_000)
    }

    #[test]
    fn test_ready_batch_creation() {
        let batch = mock_ready_batch(5);
        assert_eq!(batch.size(), 5);
        assert_eq!(batch.gas_budget, 1_000_000);
    }

    #[tokio::test]
    async fn test_spawn_controller_permits() {
        let (status_tx, _status_rx) = mpsc::channel::<StatusUpdate>(100);

        // We can't easily test the full controller without a real provider/registry,
        // so this is a placeholder test
        // TODO: Add proper controller tests with mock registry

        // Just verify the channel was created
        drop(status_tx);
    }

    // ========================================================================
    // Task Executor Tests
    // ========================================================================

    #[tokio::test]
    async fn test_shutdown_signal() {
        let (signal, shutdown) = shutdown_signal();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            signal.fire();
        });

        shutdown.await;
    }

    #[tokio::test]
    async fn test_spawn_critical_panic() {
        let (panic_tx, mut panic_rx) = mpsc::unbounded_channel();
        let (_signal, shutdown) = shutdown_signal();

        spawn_critical("test_task", shutdown, panic_tx, async {
            panic!("test panic");
        });

        let err = panic_rx.recv().await.unwrap();
        assert_eq!(err.task_name(), "test_task");
        assert_eq!(err.error(), Some("test panic"));
    }

    #[tokio::test]
    async fn test_spawn_critical_shutdown() {
        let (panic_tx, mut panic_rx) = mpsc::unbounded_channel();
        let (signal, shutdown) = shutdown_signal();
        let ran = Arc::new(AtomicBool::new(false));
        let ran_clone = ran.clone();

        spawn_critical("test_task", shutdown, panic_tx, async move {
            ran_clone.store(true, Ordering::SeqCst);
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(ran.load(Ordering::SeqCst));

        signal.fire();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // No panic should have been sent
        assert!(panic_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_spawn_with_signal() {
        let (signal, shutdown) = shutdown_signal();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        spawn_with_signal(shutdown, |shutdown| async move {
            shutdown.await;
            completed_clone.store(true, Ordering::SeqCst);
        });

        signal.fire();
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(completed.load(Ordering::SeqCst));
    }
}
