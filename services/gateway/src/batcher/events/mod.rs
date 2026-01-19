//! Events multiplexer for the gateway batcher.
//!
//! Provides high-performance event routing with subscription-based handlers.

mod builder;
mod handlers;

// Re-export public API
pub use builder::{CommandReceiver, EventsMultiplexerBuilder};
pub use handlers::{LoggingHandler, MetricsHandler, OpAcceptedHandler, StatusSyncHandler};

use crate::batcher::types::OpEnvelopeInner;
use crossbeam_channel::{self as channel, Receiver, Sender, TrySendError};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use strum::{EnumCount, EnumDiscriminants};
use tokio::sync::oneshot;
use world_id_core::types::{GatewayErrorCode, GatewayRequestKind};

// ============================================================================
// Types
// ============================================================================

/// All possible events in the system.
#[derive(Debug, Clone, EnumDiscriminants)]
#[strum_discriminants(name(EventType))]
#[strum_discriminants(derive(Hash, EnumCount))]
#[strum_discriminants(repr(u8))]
pub enum Event {
    // Operation lifecycle
    OpReceived {
        op_id: uuid::Uuid,
        op_type: &'static str,
    },
    OpValidated {
        op_id: uuid::Uuid,
    },
    OpSimulated {
        op_id: uuid::Uuid,
        gas_estimate: u64,
    },
    OpBatched {
        op_id: uuid::Uuid,
        batch_id: uuid::Uuid,
    },
    OpSubmitted {
        op_id: uuid::Uuid,
        tx_hash: alloy::primitives::B256,
    },
    OpFinalized {
        op_id: uuid::Uuid,
        tx_hash: alloy::primitives::B256,
        block_number: Option<u64>,
    },
    OpFailed {
        op_id: uuid::Uuid,
        stage: &'static str,
        reason: Arc<str>,
        error_code: GatewayErrorCode,
    },

    // Batch lifecycle
    BatchCreated {
        batch_id: uuid::Uuid,
        op_count: usize,
        gas_budget: u64,
    },
    BatchSpawned {
        batch_id: uuid::Uuid,
    },
    BatchSimulated {
        batch_id: uuid::Uuid,
        success_count: usize,
        failed_count: usize,
    },
    BatchSubmitted {
        batch_id: uuid::Uuid,
        tx_hash: alloy::primitives::B256,
    },
    BatchFinalized {
        batch_id: uuid::Uuid,
        tx_hash: Option<alloy::primitives::B256>,
        success_count: usize,
        failed_count: usize,
        duration_ms: u64,
    },
    BatchFailed {
        batch_id: uuid::Uuid,
        reason: Arc<str>,
    },

    // System events
    CapacityAvailable {
        current_depth: usize,
        max_depth: usize,
    },
    OpAccepted {
        op_id: uuid::Uuid,
        kind: GatewayRequestKind,
    },
}

impl Event {
    #[inline]
    pub fn discriminant(&self) -> usize {
        let event_type: EventType = self.into();
        unsafe { std::mem::transmute::<EventType, u8>(event_type) as usize }
    }
}

#[derive(Debug, Clone)]
pub enum SubmitResult {
    Accepted {
        op_id: uuid::Uuid,
    },
    Rejected {
        reason: Arc<str>,
        error_code: GatewayErrorCode,
    },
}

#[derive(Debug, Clone)]
pub enum OpResult {
    Finalized {
        tx_hash: alloy::primitives::B256,
        block_number: u64,
    },
    Failed {
        reason: Arc<str>,
        error_code: GatewayErrorCode,
    },
}

pub enum Command {
    SubmitOp {
        op: OpEnvelopeInner,
        ack_tx: oneshot::Sender<SubmitResult>,
        result_tx: oneshot::Sender<OpResult>,
    },
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SubmitError {
    #[error("batcher queue is full")]
    QueueFull,
    #[error("batcher is shutting down")]
    Shutdown,
    #[error("acknowledgment timeout")]
    AckTimeout,
}

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum BuildError {
    #[error("event channel capacity must be > 0")]
    InvalidEventCapacity,
    #[error("command channel capacity must be > 0")]
    InvalidCommandCapacity,
}

pub(crate) struct Envelope {
    pub event: Event,
}

/// Registry for waiting on event completion.
#[derive(Default)]
pub struct Waiters {
    waiters: Mutex<HashMap<uuid::Uuid, oneshot::Sender<()>>>,
}

impl Waiters {
    pub fn new() -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, op_id: uuid::Uuid) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().unwrap().insert(op_id, tx);
        rx
    }

    pub fn notify(&self, op_id: &uuid::Uuid) {
        if let Some(tx) = self.waiters.lock().unwrap().remove(op_id) {
            let _ = tx.send(());
        }
    }
}

// ============================================================================
// Handler Trait
// ============================================================================

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub trait EventHandler: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn handle(&self, _event: &Event) {}
    fn handle_async(&self, _event: &Event) -> Option<BoxFuture<()>> {
        None
    }
    fn is_async(&self) -> bool {
        false
    }
}

impl<F> EventHandler for F
where
    F: Fn(&Event) -> BoxFuture<()> + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        std::any::type_name::<F>()
    }

    fn is_async(&self) -> bool {
        true
    }

    fn handle_async(&self, event: &Event) -> Option<BoxFuture<()>> {
        Some((self)(event))
    }
}

pub(crate) struct BoxedHandler {
    inner: Arc<dyn EventHandler>,
}

impl BoxedHandler {
    pub fn new(handler: Arc<dyn EventHandler>) -> Self {
        Self { inner: handler }
    }

    #[inline]
    pub fn name(&self) -> &'static str {
        self.inner.name()
    }

    #[inline]
    pub fn is_async(&self) -> bool {
        self.inner.is_async()
    }

    pub fn handle(&self, event: &Event) {
        self.inner.handle(event);
    }

    pub fn handle_async(&self, event: &Event) -> Option<BoxFuture<()>> {
        self.inner.handle_async(event)
    }
}

impl Clone for BoxedHandler {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub(crate) struct SubscriptionTable {
    handlers: Vec<Vec<BoxedHandler>>,
    global_handlers: Vec<BoxedHandler>,
}

impl SubscriptionTable {
    pub fn new(event_type_count: usize) -> Self {
        Self {
            handlers: (0..event_type_count).map(|_| Vec::new()).collect(),
            global_handlers: Vec::new(),
        }
    }

    pub fn subscribe(&mut self, event_type: EventType, handler: BoxedHandler) {
        let idx = event_type as usize;
        if idx < self.handlers.len() {
            self.handlers[idx].push(handler);
        }
    }

    pub fn subscribe_all(&mut self, handler: BoxedHandler) {
        self.global_handlers.push(handler);
    }

    #[inline]
    pub fn get_handlers(&self, event: &Event) -> impl Iterator<Item = &BoxedHandler> {
        let idx = event.discriminant();
        let specific = self
            .handlers
            .get(idx)
            .map(|v| v.iter())
            .into_iter()
            .flatten();
        let global = self.global_handlers.iter();
        specific.chain(global)
    }

    pub fn has_async_handlers(&self) -> bool {
        self.global_handlers.iter().any(|h| h.is_async())
            || self.handlers.iter().any(|v| v.iter().any(|h| h.is_async()))
    }
}

// ============================================================================
// Metrics (internal)
// ============================================================================

pub(crate) struct EventsMetrics {
    pub events_dropped: AtomicU64,
    pub handler_panics: AtomicU64,
    pub queue_depth: AtomicUsize,
}

impl EventsMetrics {
    pub fn new() -> Self {
        Self {
            events_dropped: AtomicU64::new(0),
            handler_panics: AtomicU64::new(0),
            queue_depth: AtomicUsize::new(0),
        }
    }
}

impl Default for EventsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Event Processor
// ============================================================================

pub(crate) struct EventProcessor {
    rx: Receiver<Envelope>,
    subscriptions: SubscriptionTable,
    metrics: Arc<EventsMetrics>,
    shutdown: Arc<AtomicBool>,
    runtime: Option<tokio::runtime::Handle>,
}

impl EventProcessor {
    pub fn new(
        rx: Receiver<Envelope>,
        subscriptions: SubscriptionTable,
        metrics: Arc<EventsMetrics>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let runtime = if subscriptions.has_async_handlers() {
            Some(tokio::runtime::Handle::current())
        } else {
            None
        };

        Self {
            rx,
            subscriptions,
            metrics,
            shutdown,
            runtime,
        }
    }

    pub fn run(self) {
        tracing::info!(target: "world_id_gateway::batcher::events", "event_processor.started");

        while !self.shutdown.load(Ordering::Relaxed) {
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(envelope) => {
                    self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                    self.process(envelope);
                }
                Err(channel::RecvTimeoutError::Timeout) => continue,
                Err(channel::RecvTimeoutError::Disconnected) => {
                    tracing::info!(target: "world_id_gateway::batcher::events", "event_processor.channel_closed");
                    break;
                }
            }
        }

        self.drain();
        tracing::info!(target: "world_id_gateway::batcher::events", "event_processor.stopped");
    }

    fn process(&self, envelope: Envelope) {
        for handler in self.subscriptions.get_handlers(&envelope.event) {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if handler.is_async() {
                    if let (Some(runtime), Some(fut)) =
                        (&self.runtime, handler.handle_async(&envelope.event))
                    {
                        runtime.spawn(fut);
                    }
                } else {
                    handler.handle(&envelope.event);
                }
            }));

            if let Err(e) = result {
                tracing::error!(target: "world_id_gateway::batcher::events", handler = handler.name(), error = ?e, "event_handler.panic");
                self.metrics.handler_panics.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn drain(&self) {
        let mut drained = 0;
        while let Ok(envelope) = self.rx.try_recv() {
            self.process(envelope);
            drained += 1;
        }
        if drained > 0 {
            tracing::info!(target: "world_id_gateway::batcher::events", count = drained, "event_processor.drained");
        }
    }
}

// ============================================================================
// Events Multiplexer
// ============================================================================

struct EventsMultiplexerInner {
    event_tx: Sender<Envelope>,
    command_tx: Sender<Command>,
    metrics: Arc<EventsMetrics>,
    shutdown: Arc<AtomicBool>,
    waiters: Arc<Waiters>,
}

#[derive(Clone)]
pub struct EventsMultiplexer {
    inner: Arc<EventsMultiplexerInner>,
}

impl EventsMultiplexer {
    pub(crate) fn new(
        event_tx: Sender<Envelope>,
        command_tx: Sender<Command>,
        metrics: Arc<EventsMetrics>,
        shutdown: Arc<AtomicBool>,
        waiters: Arc<Waiters>,
    ) -> Self {
        Self {
            inner: Arc::new(EventsMultiplexerInner {
                event_tx,
                command_tx,
                metrics,
                shutdown,
                waiters,
            }),
        }
    }

    #[inline]
    pub fn publish(&self, event: Event) {
        let envelope = Envelope { event };

        match self.inner.event_tx.try_send(envelope) {
            Ok(()) => {
                self.inner
                    .metrics
                    .queue_depth
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                self.inner
                    .metrics
                    .events_dropped
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(target: "world_id_gateway::batcher::events", "event_bus.dropped: channel full");
            }
            Err(TrySendError::Disconnected(_)) => {
                tracing::error!(target: "world_id_gateway::batcher::events", "event_bus.disconnected: processor stopped");
            }
        }
    }

    #[inline]
    pub async fn submit_op(
        &self,
        op: OpEnvelopeInner,
    ) -> Result<(SubmitResult, oneshot::Receiver<OpResult>), SubmitError> {
        let op_id = op.id;
        let op_type = op.op.type_name();

        let (ack_tx, ack_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();

        self.inner
            .command_tx
            .try_send(Command::SubmitOp {
                op,
                ack_tx,
                result_tx,
            })
            .map_err(|e| match e {
                TrySendError::Full(_) => SubmitError::QueueFull,
                TrySendError::Disconnected(_) => SubmitError::Shutdown,
            })?;

        let ack = ack_rx.await.map_err(|_| SubmitError::Shutdown)?;

        if matches!(ack, SubmitResult::Accepted { .. }) {
            self.publish(Event::OpReceived { op_id, op_type });
        }

        Ok((ack, result_rx))
    }

    #[inline]
    pub fn try_submit_op(
        &self,
        op: OpEnvelopeInner,
    ) -> Result<oneshot::Receiver<OpResult>, SubmitError> {
        let op_id = op.id;
        let op_type = op.op.type_name();

        let (ack_tx, _ack_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();

        self.inner
            .command_tx
            .try_send(Command::SubmitOp {
                op,
                ack_tx,
                result_tx,
            })
            .map_err(|e| match e {
                TrySendError::Full(_) => SubmitError::QueueFull,
                TrySendError::Disconnected(_) => SubmitError::Shutdown,
            })?;

        self.publish(Event::OpReceived { op_id, op_type });
        Ok(result_rx)
    }

    pub async fn submit_and_wait(
        &self,
        op: OpEnvelopeInner,
    ) -> Result<oneshot::Receiver<OpResult>, SubmitError> {
        let op_id = op.id;
        let op_type = op.op.type_name();

        let ready_rx = self.inner.waiters.register(op_id);

        let (ack_tx, ack_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();

        self.inner
            .command_tx
            .try_send(Command::SubmitOp {
                op,
                ack_tx,
                result_tx,
            })
            .map_err(|e| match e {
                TrySendError::Full(_) => SubmitError::QueueFull,
                TrySendError::Disconnected(_) => SubmitError::Shutdown,
            })?;

        let ack = ack_rx.await.map_err(|_| SubmitError::Shutdown)?;

        if let SubmitResult::Rejected { reason, .. } = ack {
            tracing::warn!(target: "world_id_gateway::batcher::events", op_id = %op_id, reason = %reason, "op.rejected");
            return Err(SubmitError::Shutdown);
        }

        self.publish(Event::OpReceived { op_id, op_type });
        let _ = ready_rx.await;

        Ok(result_rx)
    }

    pub fn waiters(&self) -> &Arc<Waiters> {
        &self.inner.waiters
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    struct CountingHandler {
        count: AtomicU32,
    }

    impl CountingHandler {
        fn new() -> Self {
            Self {
                count: AtomicU32::new(0),
            }
        }

        fn count(&self) -> u32 {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl EventHandler for CountingHandler {
        fn name(&self) -> &'static str {
            "counting"
        }

        fn handle(&self, _event: &Event) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct SharedCountingHandler(Arc<CountingHandler>);

    impl EventHandler for SharedCountingHandler {
        fn name(&self) -> &'static str {
            self.0.name()
        }

        fn handle(&self, event: &Event) {
            self.0.handle(event)
        }
    }

    #[test]
    fn test_publish_receive() {
        let counter = Arc::new(CountingHandler::new());

        let (bus, processor, _cmd_rx) = EventsMultiplexerBuilder::new()
            .event_capacity(100)
            .subscribe_all(SharedCountingHandler(counter.clone()))
            .build()
            .unwrap();

        let handle = std::thread::spawn(move || processor.run());

        for _ in 0..10 {
            bus.publish(Event::OpValidated {
                op_id: uuid::Uuid::new_v4(),
            });
        }

        std::thread::sleep(Duration::from_millis(200));

        bus.shutdown();
        drop(bus);
        handle.join().unwrap();

        assert_eq!(counter.count(), 10);
    }

    #[test]
    fn test_selective_subscription() {
        let op_counter = Arc::new(CountingHandler::new());
        let batch_counter = Arc::new(CountingHandler::new());

        let (bus, processor, _cmd_rx) = EventsMultiplexerBuilder::new()
            .subscribe(
                EventType::OpFinalized,
                SharedCountingHandler(op_counter.clone()),
            )
            .subscribe(
                EventType::BatchFinalized,
                SharedCountingHandler(batch_counter.clone()),
            )
            .build()
            .unwrap();

        let handle = std::thread::spawn(move || processor.run());

        bus.publish(Event::OpFinalized {
            op_id: uuid::Uuid::new_v4(),
            tx_hash: alloy::primitives::B256::ZERO,
            block_number: Some(100),
        });
        bus.publish(Event::BatchFinalized {
            batch_id: uuid::Uuid::new_v4(),
            tx_hash: Some(alloy::primitives::B256::ZERO),
            success_count: 5,
            failed_count: 0,
            duration_ms: 1000,
        });
        bus.publish(Event::OpValidated {
            op_id: uuid::Uuid::new_v4(),
        });

        std::thread::sleep(Duration::from_millis(200));
        bus.shutdown();
        drop(bus);
        handle.join().unwrap();

        assert_eq!(op_counter.count(), 1);
        assert_eq!(batch_counter.count(), 1);
    }

    #[test]
    fn test_build_validation() {
        let result = EventsMultiplexerBuilder::new().event_capacity(0).build();
        assert!(matches!(result, Err(BuildError::InvalidEventCapacity)));

        let result = EventsMultiplexerBuilder::new().command_capacity(0).build();
        assert!(matches!(result, Err(BuildError::InvalidCommandCapacity)));
    }
}
