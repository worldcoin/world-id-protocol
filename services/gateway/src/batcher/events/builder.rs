//! Builder for constructing an EventsMultiplexer system.

use super::{
    BoxedHandler, BuildError, Command, EventHandler, EventProcessor, EventType, EventsMetrics,
    EventsMultiplexer, SubscriptionTable, Waiters,
};
use crossbeam_channel as channel;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use strum::EnumCount;

/// Receiver for commands from the EventBus.
pub struct CommandReceiver {
    rx: channel::Receiver<Command>,
}

impl CommandReceiver {
    pub async fn recv_timeout(&self, timeout: std::time::Duration) -> Option<Command> {
        let rx = self.rx.clone();
        tokio::task::spawn_blocking(move || rx.recv_timeout(timeout).ok())
            .await
            .ok()
            .flatten()
    }
}

/// Builder for constructing an EventsMultiplexer, EventProcessor, and CommandReceiver.
pub struct EventsMultiplexerBuilder {
    event_capacity: usize,
    command_capacity: usize,
    metrics: EventsMetrics,
    subscriptions: SubscriptionTable,
    waiters: Option<Arc<Waiters>>,
}

impl Default for EventsMultiplexerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventsMultiplexerBuilder {
    pub fn new() -> Self {
        Self {
            event_capacity: 10_000,
            command_capacity: 4_096,
            metrics: EventsMetrics::new(),
            subscriptions: SubscriptionTable::new(EventType::COUNT),
            waiters: None,
        }
    }

    pub fn waiters(mut self, waiters: Arc<Waiters>) -> Self {
        self.waiters = Some(waiters);
        self
    }

    pub fn event_capacity(mut self, capacity: usize) -> Self {
        self.event_capacity = capacity;
        self
    }

    #[cfg(test)]
    pub fn command_capacity(mut self, capacity: usize) -> Self {
        self.command_capacity = capacity;
        self
    }

    pub fn subscribe_all<H: EventHandler>(mut self, handler: H) -> Self {
        let handler = self.register_handler(handler);
        self.subscriptions.subscribe_all(handler);
        self
    }

    pub fn subscribe<H: EventHandler>(mut self, event_type: EventType, handler: H) -> Self {
        let handler = self.register_handler(handler);
        self.subscriptions.subscribe(event_type, handler);
        self
    }

    pub fn subscribe_many<H: EventHandler>(
        mut self,
        event_types: &[EventType],
        handler: H,
    ) -> Self {
        let handler = self.register_handler(handler);
        for &event_type in event_types {
            self.subscriptions.subscribe(event_type, handler.clone());
        }
        self
    }

    fn register_handler<H: EventHandler>(&mut self, handler: H) -> BoxedHandler {
        BoxedHandler::new(Arc::new(handler))
    }

    pub fn build(self) -> Result<(EventsMultiplexer, EventProcessor, CommandReceiver), BuildError> {
        if self.event_capacity == 0 {
            return Err(BuildError::InvalidEventCapacity);
        }
        if self.command_capacity == 0 {
            return Err(BuildError::InvalidCommandCapacity);
        }

        let (event_tx, event_rx) = channel::bounded(self.event_capacity);
        let (command_tx, command_rx) = channel::bounded(self.command_capacity);
        let metrics = Arc::new(self.metrics);
        let shutdown = Arc::new(AtomicBool::new(false));
        let waiters = self.waiters.unwrap_or_else(|| Arc::new(Waiters::new()));

        let bus = EventsMultiplexer::new(
            event_tx,
            command_tx,
            metrics.clone(),
            shutdown.clone(),
            waiters,
        );

        let processor = EventProcessor::new(event_rx, self.subscriptions, metrics, shutdown);

        let cmd_receiver = CommandReceiver { rx: command_rx };

        Ok((bus, processor, cmd_receiver))
    }
}
