//! Unified batching system for blockchain operations.
//!
//! # Architecture
//! ```text
//! HTTP Request ──► IngressController ──► OpsBatcher ──► Batch<Queued>
//!                     (backpressure)      (ordering)        │
//!                                                    GasPolicy.compute()
//!                                                           │
//!                                             ┌─────────────┴─────────────┐
//!                                             ▼                           ▼
//!                                        simulate()                   submit()
//!                                             │                           │
//!                                             └──► Batch<Submitted> ──► confirm()
//!                                                         │
//!                                                         ▼
//!                                                  Batch<Finalized>
//! ```
//!
//! # Components
//! - **IngressController**: Rate limiting and backpressure
//! - **OpsBatcher**: Main batch processor with gas policy integration
//! - **GasPolicy**: Adaptive batch sizing based on chain conditions
//! - **ChainMonitor**: Tracks base fee trends and block utilization
//! - **EventBus**: Publishes lifecycle events for metrics/logging/status sync

mod chain;
mod event_bus;
mod gas_policy;
mod ingress;
mod metrics;
mod order;
mod request;
mod types;

// Public API - Event Bus
pub use event_bus::{
    BatcherEvent, EventBus, EventBusConfig, EventHandler, HandlerFn, Stage, Subscriber,
    handler_fn, logging_handler, metrics_handler, status_sync_handler,
};

// Public API - Request/Batch lifecycle
pub use ingress::{BackpressureError, OpsBatcherHandle};
pub use metrics::OpsBatcherMetrics;
pub use request::{Assigned, Batch, BatchOps, Request, Submitted, run_batch};
pub use types::{
    ChainState, InsertAuthenticatorOp, OpEnvelopeInner, Operation,
    RecoverAccountOp, RemoveAuthenticatorOp, UpdateAuthenticatorOp,
};

// Re-export macros
pub use crate::init_event_handlers;

// Internal imports
use alloy::primitives::{address, Address, Bytes, B256};
use alloy::providers::{DynProvider, Provider};
use backon::{ConstantBuilder, Retryable};
use chain::{ChainMonitor, ChainMonitorConfig};
use gas_policy::{GasPolicy, GasPolicyConfig, GasPolicyTrait};
use order::{OrderingPolicy, SignupFifoOrdering};
use std::collections::{BinaryHeap, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;
use world_id_core::types::parse_contract_error;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

// ═══════════════════════════════════════════════════════════════════════════
// RPC ERROR CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════

/// RPC operation error with retryability classification.
#[derive(Debug, Clone)]
pub enum RpcError {
    /// Transient error - safe to retry (network issues, rate limits, timeouts)
    Retryable(String),
    /// Permanent error - should not retry (invalid params, reverts, auth errors)
    Permanent(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retryable(msg) => write!(f, "retryable: {msg}"),
            Self::Permanent(msg) => write!(f, "permanent: {msg}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    /// Classify an RPC error as retryable or permanent.
    ///
    /// **Principle**: Only WorldIdRegistry contract errors are permanent.
    /// Everything else (network, timeouts, rate limits, etc.) is retryable.
    ///
    /// Uses `parse_contract_error` to detect known WorldIdRegistry error selectors:
    /// - AuthenticatorAddressAlreadyInUse
    /// - AuthenticatorDoesNotExist
    /// - MismatchedSignatureNonce
    /// - PubkeyIdInUse
    /// - PubkeyIdOutOfBounds
    /// - AuthenticatorDoesNotBelongToAccount
    pub fn classify(error: impl std::fmt::Display) -> Self {
        let msg = error.to_string();

        // Check for WorldIdRegistry contract errors using parse_contract_error
        // If it's a known contract error (not BadRequest), it's permanent
        if !matches!(
            parse_contract_error(&msg),
            world_id_core::types::GatewayErrorCode::BadRequest
        ) {
            return Self::Permanent(msg);
        }

        // Everything else is retryable
        Self::Retryable(msg)
    }

    /// Create a retryable error with a message.
    pub fn retryable(msg: impl Into<String>) -> Self {
        Self::Retryable(msg.into())
    }

    /// Create a permanent error with a message.
    pub fn permanent(msg: impl Into<String>) -> Self {
        Self::Permanent(msg.into())
    }

    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }

    /// Get the inner error message.
    pub fn message(&self) -> &str {
        match self {
            Self::Retryable(msg) | Self::Permanent(msg) => msg,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RETRY UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for retry behavior.
#[derive(Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_attempts: usize,
    /// Delay between retry attempts.
    pub delay: Duration,
    /// Name of the operation for logging.
    pub operation_name: &'static str,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 60,
            delay: Duration::from_millis(100),
            operation_name: "rpc_call",
        }
    }
}

impl RetryConfig {
    pub fn new(operation_name: &'static str) -> Self {
        Self {
            operation_name,
            ..Default::default()
        }
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// Execute an async operation with backoff retry, only retrying retryable errors.
///
/// Uses backon for retry logic. The operation should return `Result<T, RpcError>`.
/// Only `RpcError::Retryable` errors will trigger retries.
///
/// Includes:
/// - `when`: Only retry if error is retryable
/// - `notify`: Log each retry attempt
pub async fn with_retry<F, Fut, T>(
    operation: F,
    config: RetryConfig,
) -> Result<T, RpcError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, RpcError>>,
{
    let backoff = ConstantBuilder::default()
        .with_delay(config.delay)
        .with_max_times(config.max_attempts);

    let operation_name = config.operation_name;

    operation
        .retry(backoff)
        .when(|e: &RpcError| e.is_retryable())
        .notify(|err: &RpcError, duration: Duration| {
            tracing::debug!(
                operation = operation_name,
                error = %err,
                retry_after_ms = duration.as_millis(),
                "retrying operation"
            );
        })
        .await
}

// ═══════════════════════════════════════════════════════════════════════════
// MULTICALL3 CONTRACT
// ═══════════════════════════════════════════════════════════════════════════

pub const MULTICALL3_ADDR: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) external payable returns (Result[] memory returnData);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
pub struct OpsBatcherConfig {
    /// How long to wait before processing a batch.
    pub batch_window: Duration,
    /// Maximum operations per batch.
    pub max_batch_ops: usize,
    /// Maximum concurrent batch submissions.
    pub max_concurrent: usize,
    /// Number of block confirmations required before considering finalized.
    pub confirmation_depth: u64,
    /// Gas policy configuration.
    pub gas_policy: GasPolicyConfig,
    /// Chain monitor configuration.
    pub chain_monitor: ChainMonitorConfig,
    /// Registry contract instance.
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
}

impl OpsBatcherConfig {
    pub fn new(registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>) -> Self {
        Self {
            batch_window: Duration::from_millis(500),
            max_batch_ops: 100,
            max_concurrent: 3,
            confirmation_depth: 1, // Default to 1 confirmation
            gas_policy: GasPolicyConfig::default(),
            chain_monitor: ChainMonitorConfig::default(),
            registry,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OPSBATCHER
// ═══════════════════════════════════════════════════════════════════════════

/// Main batch processor that coordinates all batching components.
///
/// Generic over:
/// - `G`: Gas policy for computing batch sizes
/// - `P`: Ordering policy for prioritizing operations
pub struct OpsBatcher<G = GasPolicy, P = SignupFifoOrdering<OpEnvelopeInner>>
where
    G: GasPolicyTrait,
    P: OrderingPolicy,
{
    rx: mpsc::Receiver<OpEnvelopeInner>,
    provider: Arc<DynProvider>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    config: OpsBatcherConfig,
    metrics: OpsBatcherMetrics,
    event_bus: EventBus,
    gas_policy: G,
    chain_monitor: Arc<ChainMonitor<DynProvider>>,
    shutdown_tx: broadcast::Sender<()>,
    _ordering: std::marker::PhantomData<P>,
}

impl OpsBatcher {
    /// Create a new OpsBatcher with default GasPolicy and SignupFifoOrdering.
    pub fn new(
        provider: Arc<DynProvider>,
        config: OpsBatcherConfig,
        metrics: OpsBatcherMetrics,
        event_bus: EventBus,
    ) -> (Self, OpsBatcherHandle) {
        let gas_policy = GasPolicy::new(config.gas_policy.clone());
        Self::with_policies(provider, config, metrics, event_bus, gas_policy)
    }
}

impl<G, P> OpsBatcher<G, P>
where
    G: GasPolicyTrait,
    P: OrderingPolicy,
{
    /// Create a new OpsBatcher with custom gas and ordering policies.
    pub fn with_policies(
        provider: Arc<DynProvider>,
        config: OpsBatcherConfig,
        metrics: OpsBatcherMetrics,
        event_bus: EventBus,
        gas_policy: G,
    ) -> (Self, OpsBatcherHandle) {
        let (tx, rx) = mpsc::channel(config.max_batch_ops * 4);
        let handle = ingress::IngressController::new(tx, ingress::IngressConfig::default());
        let registry = config.registry.clone();

        // Create chain monitor
        let chain_monitor = ChainMonitor::new(provider.clone(), config.chain_monitor.clone());

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);

        (
            Self {
                rx,
                provider,
                registry,
                config,
                metrics,
                event_bus,
                gas_policy,
                chain_monitor,
                shutdown_tx,
                _ordering: std::marker::PhantomData,
            },
            handle,
        )
    }

    /// Main run loop with integrated chain monitoring.
    pub async fn run(mut self) {
        // Spawn chain monitor
        let monitor = self.chain_monitor.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            if let Err(e) = monitor.run(shutdown_rx).await {
                tracing::error!(error = %e, "chain monitor error");
            }
        });

        // Priority queue for operation ordering
        let mut queue: BinaryHeap<P> = BinaryHeap::new();
        let mut batch_timer = tokio::time::interval(self.config.batch_window);

        tracing::info!(
            batch_window_ms = self.config.batch_window.as_millis(),
            max_batch_ops = self.config.max_batch_ops,
            "OpsBatcher started"
        );

        loop {
            tokio::select! {
                Some(op) = self.rx.recv() => {
                    // Publish received event
                    self.event_bus.publish(BatcherEvent::OpReceived {
                        op_id: op.id,
                        op_type: op.op.type_name(),
                    });

                    // Add to priority queue with ordering policy
                    queue.push(P::new(op));
                    self.metrics.set_queue_depth(queue.len());

                    // Check if we should process immediately
                    if queue.len() >= self.config.max_batch_ops {
                        self.process_batch(&mut queue).await;
                    }
                }
                _ = batch_timer.tick() => {
                    if !queue.is_empty() {
                        self.process_batch(&mut queue).await;
                    }
                }
            }
        }
    }

    /// Process a batch using gas policy for sizing.
    async fn process_batch(&self, queue: &mut BinaryHeap<P>) {
        if queue.is_empty() {
            return;
        }

        // Get current chain state
        let chain_state = self.chain_monitor.current_state();
        let queue_depth = queue.len();

        // Compute batch parameters from gas policy
        let batch_params = self.gas_policy.compute_batch_params(&chain_state, queue_depth);

        tracing::debug!(
            gas_budget = batch_params.gas_budget,
            reason = ?batch_params.reason,
            queue_depth = queue_depth,
            base_fee_gwei = chain_state.base_fee_gwei(),
            "batch.planning"
        );

        // Don't batch if at fee ceiling
        if batch_params.gas_budget == 0 {
            tracing::warn!("skipping batch: at fee ceiling");
            return;
        }

        // Drain operations from queue up to gas budget
        let mut ops = Vec::new();
        let mut gas_used = 0u64;

        while let Some(envelope) = queue.peek() {
            let op_gas = envelope.estimated_gas();

            // Check if adding this op would exceed budget or max ops
            if gas_used + op_gas > batch_params.gas_budget {
                break;
            }
            if ops.len() >= self.config.max_batch_ops {
                break;
            }

            let envelope = queue.pop().unwrap();
            gas_used += op_gas;
            ops.push(envelope.into_inner());
        }

        if ops.is_empty() {
            return;
        }

        let batch_id = Uuid::new_v4();
        let op_count = ops.len();

        // Publish batch created event
        self.event_bus.publish(BatcherEvent::BatchCreated {
            batch_id,
            op_count,
            gas_budget: batch_params.gas_budget,
        });

        let requests: Vec<_> = ops.into_iter().map(Request::from).collect();
        let start = std::time::Instant::now();

        // Run through the batch pipeline
        match run_batch(self, requests, batch_id).await {
            Ok(batch) => {
                let duration_ms = start.elapsed().as_millis() as u64;

                // Publish finalized events for each op
                for req in batch.requests() {
                    self.event_bus.publish(BatcherEvent::OpFinalized {
                        op_id: req.id,
                        tx_hash: batch.tx_hash(),
                        block_number: Some(batch.block()),
                    });
                }

                self.event_bus.publish(BatcherEvent::BatchFinalized {
                    batch_id,
                    tx_hash: Some(batch.tx_hash()),
                    success_count: batch.len(),
                    failed_count: 0,
                    duration_ms,
                });

                self.metrics.inc_batches_completed();
                self.metrics.observe_batch_duration(duration_ms);
                self.metrics.observe_batch_size(batch.len());
            }
            Err(batch) => {
                // Publish failed events for each op
                for req in batch.requests() {
                    self.event_bus.publish(BatcherEvent::OpFailed {
                        op_id: req.id,
                        stage: Stage::Failed,
                        reason: batch.reason().to_string(),
                        error_code: None,
                    });
                }

                self.event_bus.publish(BatcherEvent::BatchFailed {
                    batch_id,
                    reason: batch.reason().to_string(),
                });

                self.metrics.inc_batches_failed();
            }
        }

        self.metrics.set_queue_depth(queue.len());
    }

    /// Build calldata for an operation.
    fn build_calldata(&self, op: &OpEnvelopeInner) -> Bytes {
        match &op.op {
            Operation::InsertAuthenticator(inner) => self.registry
                .insertAuthenticator(
                    inner.leaf_index,
                    inner.new_authenticator_address,
                    inner.pubkey_id,
                    inner.new_authenticator_pubkey,
                    inner.old_commit,
                    inner.new_commit,
                    inner.signature.clone(),
                    inner.sibling_nodes.clone(),
                    inner.nonce,
                )
                .calldata()
                .clone(),
            Operation::UpdateAuthenticator(inner) => self.registry
                .updateAuthenticator(
                    inner.leaf_index,
                    inner.old_authenticator_address,
                    inner.new_authenticator_address,
                    inner.pubkey_id,
                    inner.new_authenticator_pubkey,
                    inner.old_commit,
                    inner.new_commit,
                    inner.signature.clone(),
                    inner.sibling_nodes.clone(),
                    inner.nonce,
                )
                .calldata()
                .clone(),
            Operation::RemoveAuthenticator(inner) => self.registry
                .removeAuthenticator(
                    inner.leaf_index,
                    inner.authenticator_address,
                    inner.pubkey_id,
                    inner.authenticator_pubkey,
                    inner.old_commit,
                    inner.new_commit,
                    inner.signature.clone(),
                    inner.sibling_nodes.clone(),
                    inner.nonce,
                )
                .calldata()
                .clone(),
            Operation::RecoverAccount(inner) => self.registry
                .recoverAccount(
                    inner.leaf_index,
                    inner.new_authenticator_address,
                    inner.new_authenticator_pubkey,
                    inner.old_commit,
                    inner.new_commit,
                    inner.signature.clone(),
                    inner.sibling_nodes.clone(),
                    inner.nonce,
                )
                .calldata()
                .clone(),
            Operation::CreateAccount(_) => {
                // CreateAccount uses a different batcher - should not reach here
                tracing::warn!("CreateAccount op sent to OpsBatcher");
                Bytes::new()
            }
        }
    }

    /// Build multicall Call3 structs for a batch.
    fn build_calls(&self, ops: &[Request<OpEnvelopeInner>], allow_failure: bool) -> Vec<Multicall3::Call3> {
        ops.iter()
            .map(|req| Multicall3::Call3 {
                target: *self.registry.address(),
                allowFailure: allow_failure,
                callData: self.build_calldata(&req.data),
            })
            .collect()
    }

    /// Parse revert reason from return data.
    fn parse_revert_reason(return_data: &Bytes) -> String {
        if return_data.is_empty() {
            return "unknown revert".to_string();
        }

        // Try to decode as Error(string)
        if return_data.len() >= 4 {
            // Error(string) selector: 0x08c379a0
            if return_data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
                if let Ok(decoded) = <alloy::sol_types::sol_data::String as alloy::sol_types::SolType>::abi_decode(&return_data[4..]) {
                    return decoded;
                }
            }
            // Panic(uint256) selector: 0x4e487b71
            if return_data[..4] == [0x4e, 0x48, 0x7b, 0x71] {
                return "panic".to_string();
            }
        }

        // Fall back to hex representation for custom errors
        format!("0x{}", hex::encode(return_data))
    }
}

impl<G, P> BatchOps<OpEnvelopeInner> for OpsBatcher<G, P>
where
    G: GasPolicyTrait,
    P: OrderingPolicy,
{
    /// Batch-simulate all operations using Multicall3 with allowFailure: true.
    /// Returns map of operation IDs to failure reasons for ops that would revert.
    async fn simulate(&self, batch: &Batch<Assigned, Request<OpEnvelopeInner>>) -> HashMap<Uuid, String> {
        let calls = self.build_calls(batch.requests(), true);
        if calls.is_empty() {
            return HashMap::new();
        }

        let mc = Multicall3::new(MULTICALL3_ADDR, self.provider.clone());

        // Execute simulation via eth_call (no gas spent)
        let results = match mc.aggregate3(calls).call().await {
            Ok(res) => res,
            Err(e) => {
                tracing::warn!(error = %e, "multicall simulation failed entirely");
                // If the whole simulation fails, mark all ops as failed
                return batch.requests().iter()
                    .map(|r| (r.id, format!("simulation RPC error: {e}")))
                    .collect();
            }
        };

        // Parse individual results
        let mut failures = HashMap::new();
        for (req, result) in batch.requests().iter().zip(results.iter()) {
            if !result.success {
                let reason = Self::parse_revert_reason(&result.returnData);
                let code = parse_contract_error(&reason);
                tracing::debug!(
                    id = %req.id,
                    reason = %reason,
                    code = ?code,
                    "op simulation failed"
                );
                failures.insert(req.id, reason);
            }
        }

        if !failures.is_empty() {
            tracing::info!(
                batch_id = %batch.batch_id(),
                evicted = failures.len(),
                remaining = batch.len() - failures.len(),
                "simulation evictions"
            );
            self.metrics.inc_simulation_evictions(failures.len() as u64);
        }

        failures
    }

    /// Submit batch via Multicall3 with allowFailure: false (atomic).
    async fn submit(&self, batch: &Batch<Assigned, Request<OpEnvelopeInner>>) -> Result<B256, String> {
        let calls = self.build_calls(batch.requests(), false);
        if calls.is_empty() {
            return Err("empty batch".to_string());
        }

        let mc = Multicall3::new(MULTICALL3_ADDR, self.provider.clone());

        tracing::info!(
            batch_id = %batch.batch_id(),
            ops = calls.len(),
            "batch.submitting"
        );

        self.metrics.inc_tx_submissions();

        match mc.aggregate3(calls).send().await {
            Ok(pending) => {
                let tx_hash = *pending.tx_hash();
                tracing::info!(
                    batch_id = %batch.batch_id(),
                    tx_hash = %tx_hash,
                    "batch.submitted"
                );
                Ok(tx_hash)
            }
            Err(e) => {
                let error_str = e.to_string();
                let code = parse_contract_error(&error_str);
                tracing::warn!(
                    batch_id = %batch.batch_id(),
                    error = %error_str,
                    code = ?code,
                    "batch.submit_failed"
                );
                Err(error_str)
            }
        }
    }

    /// Wait for transaction confirmation and return block number.
    ///
    /// Uses backon for retry logic and waits for `confirmation_depth` blocks.
    async fn confirm(&self, batch: &Batch<Submitted, Request<OpEnvelopeInner>>) -> Result<u64, String> {
        let tx_hash = batch.tx_hash();
        let confirmation_depth = self.config.confirmation_depth;

        tracing::debug!(
            tx_hash = %tx_hash,
            confirmation_depth = confirmation_depth,
            "batch.awaiting_confirmation"
        );

        // Step 1: Get the receipt using retry
        let provider = self.provider.clone();
        let receipt = with_retry(
            || {
                let p = provider.clone();
                async move {
                    match p.get_transaction_receipt(tx_hash).await {
                        Ok(Some(r)) => Ok(r),
                        Ok(None) => Err(RpcError::Retryable("receipt not found".to_string())),
                        Err(e) => Err(RpcError::classify(e)),
                    }
                }
            },
            RetryConfig::new("get_transaction_receipt"),
        )
        .await
        .map_err(|e| e.message().to_string())?;

        if !receipt.status() {
            return Err(format!("transaction reverted on-chain (tx: {tx_hash:#x})"));
        }

        let tx_block = receipt.block_number
            .ok_or_else(|| "no block number in receipt".to_string())?;

        // Step 2: Wait for confirmation depth
        if confirmation_depth > 1 {
            let target_block = tx_block + confirmation_depth - 1;

            tracing::debug!(
                tx_hash = %tx_hash,
                tx_block = tx_block,
                target_block = target_block,
                "batch.waiting_for_confirmations"
            );

            let provider = self.provider.clone();
            with_retry(
                || {
                    let p = provider.clone();
                    async move {
                        match p.get_block_number().await {
                            Ok(current) if current >= target_block => Ok(()),
                            Ok(current) => Err(RpcError::Retryable(format!(
                                "waiting for block {target_block}, current is {current}"
                            ))),
                            Err(e) => Err(RpcError::classify(e)),
                        }
                    }
                },
                RetryConfig::new("wait_confirmations").with_max_attempts(120),
            )
            .await
            .map_err(|e| format!("timeout waiting for {confirmation_depth} confirmations: {}", e.message()))?;
        }

        tracing::info!(
            batch_id = %batch.batch_id(),
            tx_hash = %tx_hash,
            block = tx_block,
            gas_used = receipt.gas_used,
            confirmations = confirmation_depth,
            "batch.confirmed"
        );

        Ok(tx_block)
    }
}
