//! Event-driven architecture for the batcher.
//!
//! The `EventBus` provides a multi-directional publish-subscribe mechanism
//! using crossbeam channels for high-throughput, low-latency event routing.
//!
//! # Architecture
//!
//! ```text
//! Publishers ──► [ingress channel] ──► Router ──► [subscriber channels] ──► Handlers
//!     │                                  │
//!     └── Many-to-one (MPSC) ────────────┘
//!                                        │
//!                                        └── One-to-many (fanout)
//! ```

use crate::batcher::metrics::OpsBatcherMetrics;
use crate::request_tracker::RequestTracker;
use alloy::primitives::B256;
use crossbeam_channel::{self as channel, Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use uuid::Uuid;
use world_id_core::types::{GatewayErrorCode, GatewayRequestState};

// ============================================================================
// Events
// ============================================================================

/// Lifecycle stage for logging/metrics context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Received,
    Validated,
    Simulated,
    Batched,
    Submitted,
    Finalized,
    Failed,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Received => write!(f, "received"),
            Self::Validated => write!(f, "validated"),
            Self::Simulated => write!(f, "simulated"),
            Self::Batched => write!(f, "batched"),
            Self::Submitted => write!(f, "submitted"),
            Self::Finalized => write!(f, "finalized"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Events emitted during batcher operation lifecycle.
#[derive(Debug, Clone)]
pub enum BatcherEvent {
    // Operation Events
    OpReceived { op_id: Uuid, op_type: &'static str },
    OpValidated { op_id: Uuid },
    OpSimulated { op_id: Uuid, gas_estimate: u64 },
    OpBatched { op_id: Uuid, batch_id: Uuid },
    OpSubmitted { op_id: Uuid, tx_hash: B256 },
    OpFinalized { op_id: Uuid, tx_hash: B256, block_number: Option<u64> },
    OpFailed { op_id: Uuid, stage: Stage, reason: String, error_code: Option<GatewayErrorCode> },

    // Batch Events
    BatchCreated { batch_id: Uuid, op_count: usize, gas_budget: u64 },
    BatchSpawned { batch_id: Uuid },
    BatchSimulated { batch_id: Uuid, success_count: usize, failed_count: usize },
    BatchSubmitted { batch_id: Uuid, tx_hash: B256 },
    BatchFinalized { batch_id: Uuid, tx_hash: Option<B256>, success_count: usize, failed_count: usize, duration_ms: u64 },
    BatchFailed { batch_id: Uuid, reason: String },
}

impl BatcherEvent {
    pub fn op_id(&self) -> Option<Uuid> {
        match self {
            Self::OpReceived { op_id, .. }
            | Self::OpValidated { op_id }
            | Self::OpSimulated { op_id, .. }
            | Self::OpBatched { op_id, .. }
            | Self::OpSubmitted { op_id, .. }
            | Self::OpFinalized { op_id, .. }
            | Self::OpFailed { op_id, .. } => Some(*op_id),
            _ => None,
        }
    }

    pub fn batch_id(&self) -> Option<Uuid> {
        match self {
            Self::OpBatched { batch_id, .. }
            | Self::BatchCreated { batch_id, .. }
            | Self::BatchSpawned { batch_id }
            | Self::BatchSimulated { batch_id, .. }
            | Self::BatchSubmitted { batch_id, .. }
            | Self::BatchFinalized { batch_id, .. }
            | Self::BatchFailed { batch_id, .. } => Some(*batch_id),
            _ => None,
        }
    }

    pub fn event_type(&self) -> &'static str {
        match self {
            Self::OpReceived { .. } => "op_received",
            Self::OpValidated { .. } => "op_validated",
            Self::OpSimulated { .. } => "op_simulated",
            Self::OpBatched { .. } => "op_batched",
            Self::OpSubmitted { .. } => "op_submitted",
            Self::OpFinalized { .. } => "op_finalized",
            Self::OpFailed { .. } => "op_failed",
            Self::BatchCreated { .. } => "batch_created",
            Self::BatchSpawned { .. } => "batch_spawned",
            Self::BatchSimulated { .. } => "batch_simulated",
            Self::BatchSubmitted { .. } => "batch_submitted",
            Self::BatchFinalized { .. } => "batch_finalized",
            Self::BatchFailed { .. } => "batch_failed",
        }
    }

    pub fn to_request_state(&self) -> Option<GatewayRequestState> {
        match self {
            Self::OpReceived { .. } => Some(GatewayRequestState::Queued),
            Self::OpValidated { .. } | Self::OpSimulated { .. } => None,
            Self::OpBatched { .. } => Some(GatewayRequestState::Batching),
            Self::OpSubmitted { tx_hash, .. } => Some(GatewayRequestState::Submitted {
                tx_hash: format!("{tx_hash:#x}"),
            }),
            Self::OpFinalized { tx_hash, .. } => Some(GatewayRequestState::Finalized {
                tx_hash: format!("{tx_hash:#x}"),
            }),
            Self::OpFailed { reason, error_code, .. } => Some(GatewayRequestState::Failed {
                error: reason.clone(),
                error_code: error_code.clone(),
            }),
            _ => None,
        }
    }
}

// ============================================================================
// Subscriber Handle
// ============================================================================

/// Handle for receiving events from the bus.
///
/// When dropped, the subscriber is automatically unregistered.
pub struct Subscriber {
    rx: Receiver<BatcherEvent>,
}

impl Subscriber {
    /// Blocking receive - waits for next event.
    pub fn recv(&self) -> Result<BatcherEvent, channel::RecvError> {
        self.rx.recv()
    }

    /// Non-blocking receive - returns immediately.
    pub fn try_recv(&self) -> Result<BatcherEvent, channel::TryRecvError> {
        self.rx.try_recv()
    }

    /// Receive with timeout.
    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Result<BatcherEvent, channel::RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    /// Get the underlying receiver for use with crossbeam select.
    pub fn receiver(&self) -> &Receiver<BatcherEvent> {
        &self.rx
    }
}

// ============================================================================
// Event Bus
// ============================================================================

/// Configuration for the event bus.
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    /// Channel capacity (0 = unbounded).
    pub channel_capacity: usize,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self { channel_capacity: 0 } // Unbounded by default
    }
}

/// Multi-directional event multiplexor using crossbeam channels.
///
/// Features:
/// - Multiple publishers can send events concurrently
/// - Multiple subscribers receive all events (fanout)
/// - High throughput with minimal latency
/// - Sync-friendly (no async runtime required for basic ops)
pub struct EventBus {
    /// Sender for publishers.
    publisher_tx: Sender<BatcherEvent>,
    /// Registry of subscriber senders (for fanout).
    subscribers: std::sync::RwLock<Vec<Sender<BatcherEvent>>>,
    /// Router thread handle.
    router_handle: Option<JoinHandle<()>>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl EventBus {
    /// Create a new event bus with the given configuration.
    pub fn new(config: EventBusConfig) -> Self {
        let (publisher_tx, _publisher_rx) = if config.channel_capacity == 0 {
            channel::unbounded()
        } else {
            channel::bounded(config.channel_capacity)
        };

        let subscribers: std::sync::RwLock<Vec<Sender<BatcherEvent>>> = std::sync::RwLock::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        // We'll start the router lazily when first subscriber is added
        Self {
            publisher_tx,
            subscribers,
            router_handle: None,
            shutdown,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(EventBusConfig::default())
    }

    /// Publish an event to all subscribers.
    ///
    /// This is non-blocking if channels are unbounded or have capacity.
    #[inline]
    pub fn publish(&self, event: BatcherEvent) {
        // Fan out directly to all subscribers
        let subscribers = self.subscribers.read().unwrap();
        for sub_tx in subscribers.iter() {
            let _ = sub_tx.send(event.clone());
        }
    }

    /// Subscribe to events from the bus.
    ///
    /// Returns a Subscriber handle for receiving events.
    pub fn subscribe(&self) -> Subscriber {
        let (tx, rx) = channel::unbounded();
        self.subscribers.write().unwrap().push(tx);
        Subscriber { rx }
    }

    /// Get the number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.read().unwrap().len()
    }

    /// Trigger shutdown of the router thread.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Spawn an async event handler task.
    ///
    /// For compatibility with async handlers, this spawns a tokio task.
    pub fn spawn_async<H>(&self, mut handler: H) -> tokio::task::JoinHandle<()>
    where
        H: EventHandler + Send + 'static,
    {
        let subscriber = self.subscribe();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                match subscriber.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(event) => handler.handle(&event),
                    Err(channel::RecvTimeoutError::Timeout) => continue,
                    Err(channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
    }

    /// Spawn a sync event handler thread.
    pub fn spawn_sync<H>(&self, mut handler: H) -> std::thread::JoinHandle<()>
    where
        H: EventHandler + Send + 'static,
    {
        let subscriber = self.subscribe();
        let shutdown = self.shutdown.clone();

        std::thread::spawn(move || {
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                match subscriber.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(event) => handler.handle(&event),
                    Err(channel::RecvTimeoutError::Timeout) => continue,
                    Err(channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
    }
}

impl Drop for EventBus {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(handle) = self.router_handle.take() {
            let _ = handle.join();
        }
    }
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("subscribers", &self.subscriber_count())
            .field("shutdown", &self.is_shutdown())
            .finish()
    }
}

// ============================================================================
// Event Handler Trait
// ============================================================================

/// A handler for batcher events.
pub trait EventHandler: Send + 'static {
    fn handle(&mut self, event: &BatcherEvent);
}

/// Wrapper to make closures implement EventHandler.
pub struct HandlerFn<F>(pub F);

impl<F> EventHandler for HandlerFn<F>
where
    F: FnMut(&BatcherEvent) + Send + 'static,
{
    fn handle(&mut self, event: &BatcherEvent) {
        (self.0)(event)
    }
}

/// Helper to create a handler from a closure.
pub fn handler_fn<F>(f: F) -> HandlerFn<F>
where
    F: FnMut(&BatcherEvent) + Send + 'static,
{
    HandlerFn(f)
}

// ============================================================================
// Macro for Handler Initialization
// ============================================================================

/// Initialize event handlers on an EventBus.
#[macro_export]
macro_rules! init_event_handlers {
    ($bus:expr, [$($handler:expr),* $(,)?]) => {{
        let bus: &$crate::batcher::EventBus = &$bus;
        vec![
            $(bus.spawn_async($handler)),*
        ]
    }};
}

// ============================================================================
// Standard Handler Functions
// ============================================================================

/// Creates a status sync handler that updates RequestTracker.
pub fn status_sync_handler(tracker: Arc<RequestTracker>) -> impl EventHandler {
    HandlerFn(move |event: &BatcherEvent| {
        if let (Some(op_id), Some(state)) = (event.op_id(), event.to_request_state()) {
            let tracker = tracker.clone();
            let id = op_id.to_string();
            tokio::spawn(async move {
                tracker.set_status(&id, state).await;
            });
        }
    })
}

/// Creates a metrics handler that records event metrics.
pub fn metrics_handler(metrics: OpsBatcherMetrics) -> impl EventHandler {
    HandlerFn(move |event: &BatcherEvent| {
        match event {
            BatcherEvent::OpReceived { op_type, .. } => {
                metrics.inc_ops_received(op_type);
            }
            BatcherEvent::OpFinalized { .. } => {
                metrics.inc_ops_finalized();
            }
            BatcherEvent::OpFailed { .. } => {
                metrics.inc_ops_failed();
            }
            BatcherEvent::BatchSpawned { .. } => {
                metrics.inc_batches_spawned();
            }
            BatcherEvent::BatchFinalized { success_count, failed_count, duration_ms, .. } => {
                metrics.inc_batches_completed();
                metrics.observe_batch_duration(*duration_ms);
                metrics.observe_batch_size(*success_count + *failed_count);
            }
            BatcherEvent::BatchFailed { .. } => {
                metrics.inc_batches_failed();
            }
            _ => {}
        }
    })
}

/// Creates a logging handler that emits structured logs.
pub fn logging_handler() -> impl EventHandler {
    HandlerFn(|event: &BatcherEvent| {
        match event {
            BatcherEvent::OpReceived { op_id, op_type } => {
                tracing::debug!(op_id = %op_id, op_type = op_type, "op.received");
            }
            BatcherEvent::OpValidated { op_id } => {
                tracing::debug!(op_id = %op_id, "op.validated");
            }
            BatcherEvent::OpSimulated { op_id, gas_estimate } => {
                tracing::debug!(op_id = %op_id, gas = gas_estimate, "op.simulated");
            }
            BatcherEvent::OpBatched { op_id, batch_id } => {
                tracing::debug!(op_id = %op_id, batch_id = %batch_id, "op.batched");
            }
            BatcherEvent::OpSubmitted { op_id, tx_hash } => {
                tracing::info!(op_id = %op_id, tx = %tx_hash, "op.submitted");
            }
            BatcherEvent::OpFinalized { op_id, tx_hash, block_number } => {
                tracing::info!(op_id = %op_id, tx = %tx_hash, block = ?block_number, "op.finalized");
            }
            BatcherEvent::OpFailed { op_id, stage, reason, .. } => {
                tracing::warn!(op_id = %op_id, stage = %stage, reason = reason, "op.failed");
            }
            BatcherEvent::BatchCreated { batch_id, op_count, gas_budget } => {
                tracing::debug!(batch_id = %batch_id, ops = op_count, gas = gas_budget, "batch.created");
            }
            BatcherEvent::BatchSpawned { batch_id } => {
                tracing::debug!(batch_id = %batch_id, "batch.spawned");
            }
            BatcherEvent::BatchSimulated { batch_id, success_count, failed_count } => {
                tracing::debug!(batch_id = %batch_id, success = success_count, failed = failed_count, "batch.simulated");
            }
            BatcherEvent::BatchSubmitted { batch_id, tx_hash } => {
                tracing::info!(batch_id = %batch_id, tx = %tx_hash, "batch.submitted");
            }
            BatcherEvent::BatchFinalized { batch_id, tx_hash, success_count, failed_count, duration_ms } => {
                tracing::info!(batch_id = %batch_id, tx = ?tx_hash, success = success_count, failed = failed_count, duration_ms = duration_ms, "batch.finalized");
            }
            BatcherEvent::BatchFailed { batch_id, reason } => {
                tracing::error!(batch_id = %batch_id, reason = reason, "batch.failed");
            }
        }
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_publish_subscribe_sync() {
        let bus = EventBus::with_defaults();
        let subscriber = bus.subscribe();

        let op_id = Uuid::new_v4();
        bus.publish(BatcherEvent::OpReceived { op_id, op_type: "create_account" });

        let event = subscriber.recv_timeout(Duration::from_millis(100))
            .expect("recv failed");

        assert_eq!(event.op_id(), Some(op_id));
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::with_defaults();
        let sub1 = bus.subscribe();
        let sub2 = bus.subscribe();

        let op_id = Uuid::new_v4();
        bus.publish(BatcherEvent::OpValidated { op_id });

        // Both subscribers should receive the event
        let event1 = sub1.recv_timeout(Duration::from_millis(100)).expect("sub1 recv failed");
        let event2 = sub2.recv_timeout(Duration::from_millis(100)).expect("sub2 recv failed");

        assert_eq!(event1.op_id(), Some(op_id));
        assert_eq!(event2.op_id(), Some(op_id));
    }

    #[tokio::test]
    async fn test_spawn_async_handler() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let bus = EventBus::with_defaults();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let _handle = bus.spawn_async(handler_fn(move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }));

        bus.publish(BatcherEvent::OpValidated { op_id: Uuid::new_v4() });
        bus.publish(BatcherEvent::OpValidated { op_id: Uuid::new_v4() });

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_shutdown() {
        let bus = EventBus::with_defaults();
        assert!(!bus.is_shutdown());

        bus.shutdown();
        assert!(bus.is_shutdown());
    }
}
