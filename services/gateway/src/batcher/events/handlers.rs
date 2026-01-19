//! Standard event handlers.

use super::{BoxFuture, Event, EventHandler, Waiters};
use crate::request_tracker::RequestTracker;
use std::sync::Arc;
use world_id_core::types::GatewayRequestState;

/// Macro to define a unit struct event handler with custom logic.
#[macro_export]
macro_rules! define_handler {
    (
        $name:ident, $handler_name:literal, {
            $( $variant:ident { $($field:ident),* $(,)? } => $body:expr ),* $(,)?
        }
    ) => {
        pub struct $name;

        impl $crate::batcher::events::EventHandler for $name {
            fn name(&self) -> &'static str {
                $handler_name
            }

            #[allow(unused_variables)]
            fn handle(&self, event: &$crate::batcher::events::Event) {
                match event {
                    $(
                        $crate::batcher::events::Event::$variant { $($field,)* .. } => $body,
                    )*
                    _ => {}
                }
            }
        }
    };
}

define_handler!(MetricsHandler, "metrics", {
    OpReceived {} => {
        metrics::counter!("gateway.ops.received").increment(1);
    },
    OpAccepted {} => {
        metrics::counter!("gateway.ops.accepted").increment(1);
    },
    OpValidated {} => {
        metrics::counter!("gateway.ops.validated").increment(1);
    },
    OpBatched {} => {
        metrics::counter!("gateway.ops.batched").increment(1);
    },
    OpSubmitted {} => {
        metrics::counter!("gateway.ops.submitted").increment(1);
    },
    OpFinalized {} => {
        metrics::counter!("gateway.ops.finalized").increment(1);
    },
    OpFailed {} => {
        metrics::counter!("gateway.ops.failed").increment(1);
    },
    BatchCreated { op_count } => {
        metrics::counter!("gateway.batches.created").increment(1);
        metrics::histogram!("gateway.batch.ops_count").record(*op_count as f64);
    },
    BatchSubmitted {} => {
        metrics::counter!("gateway.batches.submitted").increment(1);
    },
    BatchFinalized { duration_ms } => {
        metrics::counter!("gateway.batches.finalized").increment(1);
        metrics::histogram!("gateway.batch.duration_ms").record(*duration_ms as f64);
    },
    BatchFailed {} => {
        metrics::counter!("gateway.batches.failed").increment(1);
    },
});

const LOG_TARGET: &str = "world_id_gateway::batcher::events";

define_handler!(LoggingHandler, "logging", {
    OpReceived { op_id, op_type } => {
        tracing::debug!(target: LOG_TARGET, op_id = %op_id, op_type = op_type, "op.received");
    },
    OpFinalized { op_id, tx_hash, block_number } => {
        tracing::info!(target: LOG_TARGET, op_id = %op_id, tx = %tx_hash, block = ?block_number, "op.finalized");
    },
    OpFailed { op_id, stage, reason, error_code } => {
        tracing::warn!(target: LOG_TARGET, op_id = %op_id, stage = stage, reason = %reason, code = ?error_code, "op.failed");
    },
    BatchCreated { batch_id, op_count, gas_budget } => {
        tracing::debug!(target: LOG_TARGET, batch_id = %batch_id, ops = op_count, gas = gas_budget, "batch.created");
    },
    BatchFinalized { batch_id, tx_hash, success_count, failed_count, duration_ms } => {
        tracing::info!(target: LOG_TARGET, batch_id = %batch_id, tx = ?tx_hash, success = success_count, failed = failed_count, duration_ms = duration_ms, "batch.finalized");
    },
    BatchFailed { batch_id, reason } => {
        tracing::error!(target: LOG_TARGET, batch_id = %batch_id, reason = %reason, "batch.failed");
    },
    OpAccepted { op_id, kind } => {
        tracing::debug!(target: LOG_TARGET, op_id = %op_id, kind = ?kind, "op.accepted");
    },
});

/// Status sync handler - updates RequestTracker on terminal events.
pub struct StatusSyncHandler {
    tracker: Arc<RequestTracker>,
}

impl StatusSyncHandler {
    pub fn new(tracker: Arc<RequestTracker>) -> Self {
        Self { tracker }
    }
}

impl EventHandler for StatusSyncHandler {
    fn name(&self) -> &'static str {
        "status_sync"
    }

    fn is_async(&self) -> bool {
        true
    }

    fn handle_async(&self, event: &Event) -> Option<BoxFuture<()>> {
        let (id, state) = match event {
            Event::OpFinalized { op_id, tx_hash, .. } => (
                op_id.to_string(),
                GatewayRequestState::Finalized {
                    tx_hash: format!("{tx_hash:#x}"),
                },
            ),
            Event::OpFailed {
                op_id,
                reason,
                error_code,
                ..
            } => (
                op_id.to_string(),
                GatewayRequestState::Failed {
                    error: reason.to_string(),
                    error_code: Some(error_code.clone()),
                },
            ),
            Event::OpSubmitted { op_id, tx_hash } => (
                op_id.to_string(),
                GatewayRequestState::Submitted {
                    tx_hash: format!("{tx_hash:#x}"),
                },
            ),
            Event::OpBatched { op_id, .. } => (op_id.to_string(), GatewayRequestState::Batching),
            _ => return None,
        };

        let tracker = self.tracker.clone();
        Some(Box::pin(async move {
            tracker.set_status(&id, state).await;
        }))
    }
}

/// Op accepted handler - creates request tracking entries when ops are accepted.
pub struct OpAcceptedHandler {
    tracker: Arc<RequestTracker>,
    waiters: Arc<Waiters>,
}

impl OpAcceptedHandler {
    pub fn new(tracker: Arc<RequestTracker>, waiters: Arc<Waiters>) -> Self {
        Self { tracker, waiters }
    }
}

impl EventHandler for OpAcceptedHandler {
    fn name(&self) -> &'static str {
        "op_accepted"
    }

    fn is_async(&self) -> bool {
        true
    }

    fn handle_async(&self, event: &Event) -> Option<BoxFuture<()>> {
        let Event::OpAccepted { op_id, kind } = event else {
            return None;
        };

        let tracker = self.tracker.clone();
        let waiters = self.waiters.clone();
        let op_id = *op_id;
        let request_id = op_id.to_string();
        let kind = kind.clone();

        Some(Box::pin(async move {
            if let Err(e) = tracker.create_request(&request_id, kind).await {
                tracing::error!(
                    target: "world_id_gateway::batcher::events",
                    op_id = %request_id,
                    error = ?e,
                    "Failed to create request tracking entry"
                );
            }
            waiters.notify(&op_id);
        }))
    }
}
