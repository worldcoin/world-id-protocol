//! Ingress controller with backpressure management.
//!
//! The `IngressController` provides a handle for submitting operations to the
//! batcher with built-in backpressure. It supports both fast-path (try_submit)
//! and slow-path (submit_with_backpressure) submission methods.

use crate::batcher::types::OpEnvelopeInner;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};
use tracing::info;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during operation submission.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BackpressureError {
    #[error("queue is full")]
    QueueFull,

    #[error("submission timed out")]
    Timeout,

    #[error("batcher is shutting down")]
    Shutdown,
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the ingress controller.
#[derive(Debug, Clone)]
pub struct IngressConfig {
    /// Maximum queue depth before backpressure is applied.
    pub max_depth: usize,
    /// Default timeout for submit_with_backpressure.
    pub default_timeout: Duration,
    /// Retry interval when waiting for capacity.
    pub retry_interval: Duration,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            max_depth: 4096,
            default_timeout: Duration::from_secs(30),
            retry_interval: Duration::from_millis(10),
        }
    }
}

// ============================================================================
// Ingress Controller
// ============================================================================

/// Controller for ingressing operations with backpressure.
///
/// This is the public handle that callers use to submit operations to the
/// batcher. It provides both blocking and non-blocking submission methods.
#[derive(Clone)]
pub struct IngressController {
    /// Sender to the validation worker.
    tx: mpsc::Sender<OpEnvelopeInner>,
    /// Shared state for backpressure coordination.
    state: Arc<IngressState>,
    /// Configuration.
    config: IngressConfig,
}

/// Shared state for backpressure coordination.
struct IngressState {
    /// Current queue depth (approximate).
    depth: AtomicUsize,
    /// Maximum allowed depth.
    max_depth: usize,
    /// Notification when capacity becomes available.
    capacity_notify: Notify,
}

impl IngressController {
    /// Create a new ingress controller.
    ///
    /// # Arguments
    /// * `tx` - Channel sender to the validation worker
    /// * `config` - Ingress configuration
    pub fn new(tx: mpsc::Sender<OpEnvelopeInner>, config: IngressConfig) -> Self {
        let state = Arc::new(IngressState {
            depth: AtomicUsize::new(0),
            max_depth: config.max_depth,
            capacity_notify: Notify::new(),
        });

        Self { tx, state, config }
    }

    /// Try to submit an operation without blocking.
    ///
    /// This is the fast path - it returns immediately with an error if the
    /// queue is full or the channel is closed.
    ///
    /// # Returns
    /// * `Ok(())` if the operation was accepted
    /// * `Err(BackpressureError::QueueFull)` if the queue is at capacity
    /// * `Err(BackpressureError::Shutdown)` if the batcher is shutting down
    pub fn try_submit(&self, op: OpEnvelopeInner) -> Result<(), BackpressureError> {
        info!("ingress.try_submit_attempt");
        // Check depth first (fast path)
        let current = self.state.depth.load(Ordering::Relaxed);
        if current >= self.state.max_depth {
            tracing::debug!(
                depth = current,
                max = self.state.max_depth,
                "ingress.backpressure_applied"
            );
            return Err(BackpressureError::QueueFull);
        }

        // Try to send
        match self.tx.try_send(op) {
            Ok(()) => {
                self.state.depth.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!("ingress.channel_full");
                Err(BackpressureError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("ingress.channel_disconnected");
                Err(BackpressureError::Shutdown)
            }
        }
    }
}

// ============================================================================
// Handle (alias for external use)
// ============================================================================

/// Handle for submitting operations to the batcher.
///
/// This is an alias for `IngressController` that provides a cleaner public API.
pub type OpsBatcherHandle = IngressController;
