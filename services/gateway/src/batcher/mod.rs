//! Unified operation batching system for the World ID Gateway.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         OpsBatcher                               │
//! │  - Receives operations via OpsBatcherHandle                     │
//! │  - Runs pre-flight checks                                        │
//! │  - Orders and selects operations for batching                   │
//! │  - Spawns PendingBatchFut tasks                                 │
//! │  - Updates RequestTracker on completion                         │
//! └────────────────────┬────────────────────────────────────────────┘
//!                      │
//!        ┌─────────────┼─────────────┐
//!        │             │             │
//!        ▼             ▼             ▼
//! ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
//! │ ChainMonitor │ │AdaptiveSizer │ │ NonceTracker │
//! │              │ │              │ │              │
//! │ Tracks base  │ │ Computes     │ │ Tracks nonce │
//! │ fee trend    │ │ batch size   │ │ dependencies │
//! └──────────────┘ └──────────────┘ └──────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      PendingBatchFut                            │
//! │  - Simulates operations, evicts failures                        │
//! │  - Builds multicall transaction                                 │
//! │  - Submits and monitors for inclusion                          │
//! │  - Escalates fees on timeout                                    │
//! │  - Returns FinalizedBatch with all statuses                    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use gateway::batcher::{OpsBatcher, OpsBatcherConfig, OpsBatcherMetrics};
//!
//! // Create metrics
//! let metrics = OpsBatcherMetrics::new(&prometheus_registry)?;
//!
//! // Build batcher
//! let (batcher, handle) = OpsBatcher::new(
//!     provider,
//!     tracker,
//!     config,
//!     metrics,
//! );
//!
//! // Spawn batcher task
//! tokio::spawn(batcher.run(shutdown_tx));
//!
//! // Submit operations
//! handle.submit(operation).await?;
//! ```
mod adaptive;
mod chain_monitor;
mod controller;
mod ingress;
mod metrics;
mod ops_batcher;
mod order;
mod pending_batch;
mod pool;
mod processor;
mod status_batcher;
mod types;
mod validation_worker;

// Re-export main types
pub use adaptive::{AdaptiveConfig, AdaptiveSizer, BatchSizeDecision, BatchSizeReason};
pub use chain_monitor::{ChainMonitor, ChainMonitorConfig};
pub use controller::{
    shutdown_signal, spawn_critical, spawn_critical_blocking, spawn_with_signal, BatchResult,
    Controller, ControllerConfig, PanickedTaskError, ReadyBatch, Shutdown, Signal,
};
pub use ingress::{BackpressureError, IngressConfig, IngressController, OpsBatcherHandle};
pub use metrics::{BatchMetricsRecorder, OpsBatcherMetrics};
pub use ops_batcher::{OpsBatcher, OpsBatcherBuilder, OpsBatcherConfig};
pub use order::{NonceTracker, OrderingPolicy, SignupFifoOrdering};
pub use pending_batch::{BatchYield, MULTICALL3_ADDR};
pub use pool::{
    FailureInfo, LifecycleStage, NoopHooks, OpPool, OpPoolConfig, PoolEntry, PoolHooks,
    PoolValidationError, StatusBatcherHooks,
};
pub use processor::{OpsProcessor, OpsProcessorConfig};
pub use status_batcher::{StatusBatcher, StatusBatcherConfig, StatusFlusherHandle, StatusUpdate};
pub use types::{
    AuthenticatorOp, BatchError, BatchTiming, ChainState, CreateAccountOp, EvictionReason,
    FailureReason, FinalizedBatch, InsertAuthenticatorOp, OpEnvelopeInner, OpStatus, Operation,
    PriorityClass, RecoverAccountOp, RemoveAuthenticatorOp, UpdateAuthenticatorOp,
};
pub use validation_worker::{
    ValidatedOp, ValidationConfig, ValidationError, ValidationMetrics, ValidationWorker,
};

pub use pending_batch::Pending;
