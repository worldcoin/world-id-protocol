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

    /// Submit an operation, waiting for capacity if necessary.
    ///
    /// This is the slow path - it will wait up to `timeout` for capacity
    /// to become available.
    ///
    /// # Arguments
    /// * `op` - The operation to submit
    /// * `timeout` - Maximum time to wait for capacity
    ///
    /// # Returns
    /// * `Ok(())` if the operation was accepted
    /// * `Err(BackpressureError::Timeout)` if the timeout elapsed
    /// * `Err(BackpressureError::Shutdown)` if the batcher is shutting down
    pub async fn submit_with_backpressure(
        &self,
        op: OpEnvelopeInner,
        timeout: Duration,
    ) -> Result<(), BackpressureError> {
        let deadline = Instant::now() + timeout;
        let op_id = op.id;

        loop {
            // Try fast path first
            match self.try_submit(op.clone()) {
                Ok(()) => return Ok(()),
                Err(BackpressureError::Shutdown) => return Err(BackpressureError::Shutdown),
                Err(BackpressureError::QueueFull) => {
                    // Check timeout
                    let now = Instant::now();
                    if now >= deadline {
                        tracing::warn!(
                            op_id = %op_id,
                            "ingress.submit_timeout"
                        );
                        return Err(BackpressureError::Timeout);
                    }

                    // Wait for capacity notification or retry interval
                    let wait_time = self.config.retry_interval.min(deadline - now);
                    tokio::select! {
                        _ = self.state.capacity_notify.notified() => {
                            // Capacity may be available, try again
                        }
                        _ = tokio::time::sleep(wait_time) => {
                            // Retry after interval
                        }
                    }
                }
                Err(BackpressureError::Timeout) => {
                    // Shouldn't happen from try_submit, but handle anyway
                    return Err(BackpressureError::Timeout);
                }
            }
        }
    }

    /// Submit an operation with the default timeout.
    pub async fn submit(&self, op: OpEnvelopeInner) -> Result<(), BackpressureError> {
        self.submit_with_backpressure(op, self.config.default_timeout)
            .await
    }

    /// Signal that capacity has been freed.
    ///
    /// This should be called when operations are consumed from the queue.
    pub fn signal_capacity(&self, count: usize) {
        self.state.depth.fetch_sub(count, Ordering::Relaxed);
        self.state.capacity_notify.notify_waiters();
    }

    /// Get the current queue depth.
    pub fn depth(&self) -> usize {
        self.state.depth.load(Ordering::Relaxed)
    }

    /// Check if the queue is at or above the backpressure threshold.
    pub fn is_backpressured(&self) -> bool {
        self.depth() >= self.state.max_depth
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

// ============================================================================
// Handle (alias for external use)
// ============================================================================

/// Handle for submitting operations to the batcher.
///
/// This is an alias for `IngressController` that provides a cleaner public API.
pub type OpsBatcherHandle = IngressController;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher::types::{CreateAccountOp, Operation};
    use alloy::primitives::{Address, Bytes, U256};
    use std::time::Instant;
    use uuid::Uuid;

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

    #[tokio::test]
    async fn test_try_submit_success() {
        let (tx, mut rx) = mpsc::channel(10);
        let config = IngressConfig {
            max_depth: 100,
            ..Default::default()
        };
        let controller = IngressController::new(tx, config);

        let op = mock_op();
        assert!(controller.try_submit(op).is_ok());
        assert_eq!(controller.depth(), 1);

        // Verify the op was sent
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_try_submit_backpressure() {
        let (tx, _rx) = mpsc::channel(10);
        let config = IngressConfig {
            max_depth: 2,
            ..Default::default()
        };
        let controller = IngressController::new(tx, config);

        // Submit up to max depth
        assert!(controller.try_submit(mock_op()).is_ok());
        assert!(controller.try_submit(mock_op()).is_ok());

        // Should get backpressure error
        let result = controller.try_submit(mock_op());
        assert!(matches!(result, Err(BackpressureError::QueueFull)));
    }

    #[tokio::test]
    async fn test_signal_capacity() {
        let (tx, _rx) = mpsc::channel(10);
        let config = IngressConfig {
            max_depth: 2,
            ..Default::default()
        };
        let controller = IngressController::new(tx, config);

        controller.try_submit(mock_op()).unwrap();
        controller.try_submit(mock_op()).unwrap();
        assert_eq!(controller.depth(), 2);

        controller.signal_capacity(1);
        assert_eq!(controller.depth(), 1);

        // Should be able to submit again
        assert!(controller.try_submit(mock_op()).is_ok());
    }

    #[tokio::test]
    async fn test_submit_with_backpressure_timeout() {
        let (tx, _rx) = mpsc::channel(1);
        let config = IngressConfig {
            max_depth: 1,
            ..Default::default()
        };
        let controller = IngressController::new(tx, config);

        // Fill the queue
        controller.try_submit(mock_op()).unwrap();

        // Submit with very short timeout should fail
        let result = controller
            .submit_with_backpressure(mock_op(), Duration::from_millis(10))
            .await;
        assert!(matches!(result, Err(BackpressureError::Timeout)));
    }

    #[tokio::test]
    async fn test_submit_with_backpressure_success() {
        let (tx, mut rx) = mpsc::channel(1);
        let config = IngressConfig {
            max_depth: 1,
            ..Default::default()
        };
        let controller = IngressController::new(tx, config);
        let controller_clone = controller.clone();

        // Fill the queue
        controller.try_submit(mock_op()).unwrap();

        // Spawn a task that will free capacity after a delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = rx.recv().await;
            controller_clone.signal_capacity(1);
        });

        // Submit should eventually succeed
        let result = controller
            .submit_with_backpressure(mock_op(), Duration::from_secs(1))
            .await;
        assert!(result.is_ok());
    }
}
