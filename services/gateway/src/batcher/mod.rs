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
//! - **OpsBatcher**: Main batch processor with gas policy integration
//! - **GasPolicy**: Adaptive batch sizing based on chain conditions
//! - **ChainMonitor**: Tracks base fee trends and block utilization
//! - **EventMultiplexer**: Publishes lifecycle events for metrics/logging/status sync

mod batch;
mod chain;
mod gas_policy;
mod order;
mod types;

// Public API - Events Multiplexer
pub mod events;
pub use events::{
    Command, CommandReceiver, Event, EventType, EventsMultiplexer, EventsMultiplexerBuilder,
    LoggingHandler, MetricsHandler, OpAcceptedHandler, OpResult, StatusSyncHandler, SubmitResult,
    Waiters,
};

pub use batch::{run_batch, Assigned, Batch, BatchOps, Request, Submitted};
pub use types::{
    InsertAuthenticatorOp, OpEnvelopeInner, Operation, RecoverAccountOp, RemoveAuthenticatorOp,
    UpdateAuthenticatorOp,
};

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
use tokio::sync::broadcast;
use uuid::Uuid;
use world_id_core::types::{parse_contract_error, GatewayErrorCode};
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

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

        // Check for transient errors (InternalServerError, NotFound) - these are retryable
        // Contract errors (BadRequest) are permanent and should not be retried
        if matches!(
            parse_contract_error(&msg),
            GatewayErrorCode::InternalServerError | GatewayErrorCode::NotFound
        ) {
            return Self::Retryable(msg);
        }

        // Contract errors are permanent
        Self::Permanent(msg)
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
}

/// Execute an async operation with backoff retry, only retrying retryable errors.
///
/// Uses backon for retry logic. The operation should return `Result<T, RpcError>`.
/// Only `RpcError::Retryable` errors will trigger retries.
///
/// Includes:
/// - `when`: Only retry if error is retryable
/// - `notify`: Log each retry attempt
pub async fn with_retry<F, Fut, T>(operation: F, config: RetryConfig) -> Result<T, RpcError>
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
                target: "world_id_gateway::batcher",
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
            batch_window: Duration::from_millis(2000), // 2 seconds (block time)
            confirmation_depth: 1,
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
pub struct OpsBatcher<G = GasPolicy, P = SignupFifoOrdering>
where
    G: GasPolicyTrait,
    P: OrderingPolicy,
{
    cmd_rx: CommandReceiver,
    provider: Arc<DynProvider>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    config: OpsBatcherConfig,
    event_bus: Arc<EventsMultiplexer>,
    gas_policy: G,
    chain_monitor: Arc<ChainMonitor<DynProvider>>,
    shutdown_tx: broadcast::Sender<()>,
    /// Pending result channels for operations awaiting batch completion.
    pending_results: HashMap<Uuid, tokio::sync::oneshot::Sender<OpResult>>,
    _ordering: std::marker::PhantomData<P>,
}

impl OpsBatcher {
    /// Create a new OpsBatcher with default GasPolicy and SignupFifoOrdering.
    pub fn new(
        provider: Arc<DynProvider>,
        config: OpsBatcherConfig,
        event_bus: Arc<EventsMultiplexer>,
        cmd_rx: CommandReceiver,
    ) -> Self {
        let gas_policy = GasPolicy::new(config.gas_policy.clone());
        let registry = config.registry.clone();

        // Create chain monitor
        let chain_monitor = ChainMonitor::new(provider.clone(), config.chain_monitor.clone());

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            cmd_rx,
            provider,
            registry,
            config,
            event_bus,
            gas_policy,
            chain_monitor,
            shutdown_tx,
            pending_results: HashMap::new(),
            _ordering: std::marker::PhantomData,
        }
    }
}

impl<G, P> OpsBatcher<G, P>
where
    G: GasPolicyTrait,
    P: OrderingPolicy,
{
    /// Main run loop with integrated chain monitoring.
    pub async fn run(mut self) {
        // Spawn chain monitor
        let monitor = self.chain_monitor.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            if let Err(e) = monitor.run(shutdown_rx).await {
                tracing::error!(target: "world_id_gateway::batcher", error = %e, "chain monitor error");
            }
        });

        // Priority queue for operation ordering
        let mut queue: BinaryHeap<P> = BinaryHeap::new();
        let mut batch_timer = tokio::time::interval(self.config.batch_window);

        tracing::info!(
            target: "world_id_gateway::batcher",
            batch_window_ms = self.config.batch_window.as_millis(),
            "OpsBatcher started"
        );

        loop {
            tokio::select! {
                biased;

                // Fallback: timer expires, flush partial batch
                _ = batch_timer.tick() => {
                    self.flush_batch(&mut queue, "timer_flush").await;
                }

                // Primary: receive command and batch when at capacity
                cmd = self.cmd_rx.recv_timeout(Duration::from_millis(50)) => {
                    if let Some(cmd) = cmd {
                        self.handle_command(cmd, &mut queue);
                        self.try_batch_if_ready(&mut queue, &mut batch_timer).await;
                    }
                }
            }
        }
    }

    /// Check if queue has reached capacity and process batch if so.
    /// Returns true if a batch was processed.
    async fn try_batch_if_ready(
        &mut self,
        queue: &mut BinaryHeap<P>,
        batch_timer: &mut tokio::time::Interval,
    ) -> bool {
        if queue.is_empty() {
            return false;
        }

        let chain_state = self.chain_monitor.current_state();
        let batch_params = self
            .gas_policy
            .compute_batch_params(&chain_state, queue.len());

        let queue_gas: u64 = queue.iter().map(|e| e.estimated_gas()).sum();

        if batch_params.gas_budget > 0 && queue_gas >= batch_params.gas_budget {
            tracing::debug!(
                target: "world_id_gateway::batcher",
                queue_gas = queue_gas,
                gas_budget = batch_params.gas_budget,
                queue_depth = queue.len(),
                "batch.capacity_reached"
            );
            self.process_batch(queue, &chain_state, &batch_params).await;
            batch_timer.reset();
            return true;
        }

        false
    }

    /// Flush the current queue as a batch.
    async fn flush_batch(&mut self, queue: &mut BinaryHeap<P>, reason: &str) {
        if queue.is_empty() {
            return;
        }

        let chain_state = self.chain_monitor.current_state();
        let batch_params = self
            .gas_policy
            .compute_batch_params(&chain_state, queue.len());

        tracing::debug!(
            target: "world_id_gateway::batcher",
            queue_depth = queue.len(),
            reason = reason,
            "batch.flush"
        );
        self.process_batch(queue, &chain_state, &batch_params).await;
    }

    /// Handle a single command by adding it to the queue.
    fn handle_command(&mut self, cmd: Command, queue: &mut BinaryHeap<P>) {
        match cmd {
            Command::SubmitOp {
                op,
                ack_tx,
                result_tx,
            } => {
                let op_id = op.id;
                let kind = op.op.request_kind();

                // Store result channel for later
                self.pending_results.insert(op_id, result_tx);

                // Add to priority queue with ordering policy
                queue.push(P::new(op));

                // Send acknowledgment
                let _ = ack_tx.send(SubmitResult::Accepted { op_id });

                // Publish OpAccepted event for RequestTracker to create entry
                self.event_bus.publish(Event::OpAccepted { op_id, kind });
            }
        }
    }

    /// Process a batch using gas policy for sizing.
    async fn process_batch(
        &mut self,
        queue: &mut BinaryHeap<P>,
        chain_state: &types::ChainState,
        batch_params: &gas_policy::BatchParameters,
    ) {
        if queue.is_empty() {
            return;
        }

        tracing::debug!(
            target: "world_id_gateway::batcher",
            gas_budget = batch_params.gas_budget,
            reason = ?batch_params.reason,
            queue_depth = queue.len(),
            base_fee_gwei = chain_state.base_fee_gwei(),
            "batch.planning"
        );

        // Don't batch if at fee ceiling
        if batch_params.gas_budget == 0 {
            tracing::warn!(target: "world_id_gateway::batcher", "skipping batch: at fee ceiling");
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
        self.event_bus.publish(Event::BatchCreated {
            batch_id,
            op_count,
            gas_budget: batch_params.gas_budget,
        });

        let requests: Vec<_> = ops.into_iter().map(Request::from).collect();
        let start = std::time::Instant::now();

        // Run through the batch pipeline
        let batch_result = run_batch(self, requests, batch_id).await;

        // Handle evicted operations - re-queue retryable ones, fail permanent ones
        for (req, reason) in batch_result.evictions {
            // Check if this is a retryable failure (RPC error) vs permanent (contract revert)
            let is_retryable = reason.starts_with("simulation RPC error:");

            if is_retryable {
                // Re-queue the operation
                tracing::debug!(
                    target: "world_id_gateway::batcher",
                    op_id = %req.id,
                    reason = %reason,
                    "re-queueing evicted op (retryable)"
                );
                queue.push(P::new(req.data));
            } else {
                // Permanent failure - notify caller
                let error_code = parse_contract_error(&reason);
                let reason: Arc<str> = reason.into();

                self.event_bus.publish(Event::OpFailed {
                    op_id: req.id,
                    stage: "simulation",
                    reason: reason.clone(),
                    error_code: error_code.clone(),
                });

                if let Some(result_tx) = self.pending_results.remove(&req.id) {
                    let _ = result_tx.send(OpResult::Failed { reason, error_code });
                }
            }
        }

        // Handle the batch result
        match batch_result.result {
            Ok(batch) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let tx_hash = batch.tx_hash();
                let block_number = batch.block();

                // Publish finalized events and send results for each op
                for req in batch.requests() {
                    self.event_bus.publish(Event::OpFinalized {
                        op_id: req.id,
                        tx_hash,
                        block_number: Some(block_number),
                    });

                    // Send result to waiting caller
                    if let Some(result_tx) = self.pending_results.remove(&req.id) {
                        let _ = result_tx.send(OpResult::Finalized {
                            tx_hash,
                            block_number,
                        });
                    }
                }

                self.event_bus.publish(Event::BatchFinalized {
                    batch_id,
                    tx_hash: Some(tx_hash),
                    success_count: batch.len(),
                    failed_count: 0,
                    duration_ms,
                });
            }
            Err(batch) => {
                let reason: Arc<str> = batch.reason().to_string().into();
                let error_code = parse_contract_error(&reason);

                // Check if this is a retryable batch failure
                let is_retryable = reason.starts_with("simulation RPC error:")
                    || reason.contains("network")
                    || reason.contains("timeout");

                // Re-queue or fail ops based on whether the error is retryable
                for req in batch.requests() {
                    if is_retryable {
                        tracing::debug!(
                            target: "world_id_gateway::batcher",
                            op_id = %req.id,
                            reason = %reason,
                            "re-queueing op from failed batch (retryable)"
                        );
                        queue.push(P::new(req.data.clone()));
                    } else {
                        self.event_bus.publish(Event::OpFailed {
                            op_id: req.id,
                            stage: "batch",
                            reason: reason.clone(),
                            error_code: error_code.clone(),
                        });

                        if let Some(result_tx) = self.pending_results.remove(&req.id) {
                            let _ = result_tx.send(OpResult::Failed {
                                reason: reason.clone(),
                                error_code: error_code.clone(),
                            });
                        }
                    }
                }

                if !is_retryable {
                    self.event_bus
                        .publish(Event::BatchFailed { batch_id, reason });
                }
            }
        }
    }

    /// Build calldata for an operation.
    fn build_calldata(&self, op: &OpEnvelopeInner) -> Bytes {
        match &op.op {
            Operation::InsertAuthenticator(inner) => self
                .registry
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
            Operation::UpdateAuthenticator(inner) => self
                .registry
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
            Operation::RemoveAuthenticator(inner) => self
                .registry
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
            Operation::RecoverAccount(inner) => self
                .registry
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
                // TODO: We should batch creates here as well, but out of scope.
                // CreateAccount uses a different batcher - should not reach here
                tracing::warn!(target: "world_id_gateway::batcher", "CreateAccount op sent to OpsBatcher");
                Bytes::new()
            }
        }
    }

    /// Build multicall Call3 structs for a batch.
    fn build_calls(
        &self,
        ops: &[Request<OpEnvelopeInner>],
        allow_failure: bool,
    ) -> Vec<Multicall3::Call3> {
        ops.iter()
            .map(|req| Multicall3::Call3 {
                target: *self.registry.address(),
                allowFailure: allow_failure,
                callData: self.build_calldata(&req.data),
            })
            .collect()
    }
}

impl<G, P> BatchOps<OpEnvelopeInner> for OpsBatcher<G, P>
where
    G: GasPolicyTrait,
    P: OrderingPolicy,
{
    /// Batch-simulate all operations using Multicall3 with allowFailure: true.
    /// Returns map of operation IDs to failure reasons for ops that would revert.
    async fn simulate(
        &self,
        batch: &Batch<Assigned, Request<OpEnvelopeInner>>,
    ) -> HashMap<Uuid, String> {
        let calls = self.build_calls(batch.requests(), true);
        if calls.is_empty() {
            return HashMap::new();
        }

        // Execute simulation via eth_call with retry (no gas spent)
        let provider = self.provider.clone();
        let results: Vec<Multicall3::Result> = match with_retry(
            || {
                let mc = Multicall3::new(MULTICALL3_ADDR, provider.clone());
                let calls = calls.clone();
                async move {
                    mc.aggregate3(calls)
                        .call()
                        .await
                        .map_err(RpcError::classify)
                }
            },
            RetryConfig::new("multicall_simulation"),
        )
        .await
        {
            Ok(res) => res,
            Err(e) => {
                tracing::warn!(target: "world_id_gateway::batcher", error = %e, "multicall simulation failed entirely");
                // If the whole simulation fails, mark all ops as failed
                return batch
                    .requests()
                    .iter()
                    .map(|r| (r.id, format!("simulation RPC error: {e}")))
                    .collect();
            }
        };

        // Parse individual results
        let mut failures = HashMap::new();
        for (req, result) in batch.requests().iter().zip(results.iter()) {
            if !result.success {
                let reason = result.returnData.to_string();
                let code = parse_contract_error(&result.returnData.to_string());
                tracing::debug!(
                    target: "world_id_gateway::batcher",
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
                target: "world_id_gateway::batcher",
                batch_id = %batch.batch_id(),
                evicted = failures.len(),
                remaining = batch.len() - failures.len(),
                "simulation evictions"
            );
        }

        failures
    }

    /// Submit batch via Multicall3 with allowFailure: false (atomic).
    async fn submit(
        &self,
        batch: &Batch<Assigned, Request<OpEnvelopeInner>>,
    ) -> Result<B256, String> {
        let calls = self.build_calls(batch.requests(), false);
        if calls.is_empty() {
            return Err("empty batch".to_string());
        }

        let mc = Multicall3::new(MULTICALL3_ADDR, self.provider.clone());

        tracing::info!(
            target: "world_id_gateway::batcher",
            batch_id = %batch.batch_id(),
            ops = calls.len(),
            "batch.submitting"
        );

        match mc.aggregate3(calls).send().await {
            Ok(pending) => {
                let tx_hash = *pending.tx_hash();
                tracing::info!(
                    target: "world_id_gateway::batcher",
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
                    target: "world_id_gateway::batcher",
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
    async fn confirm(
        &self,
        batch: &Batch<Submitted, Request<OpEnvelopeInner>>,
    ) -> Result<u64, String> {
        let tx_hash = batch.tx_hash();
        let confirmation_depth = self.config.confirmation_depth;

        tracing::debug!(
            target: "world_id_gateway::batcher",
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

        let tx_block = receipt
            .block_number
            .ok_or_else(|| "no block number in receipt".to_string())?;

        // Step 2: Wait for confirmation depth
        if confirmation_depth > 1 {
            let target_block = tx_block + confirmation_depth - 1;

            tracing::debug!(
                target: "world_id_gateway::batcher",
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
                RetryConfig::new("wait_confirmations")
                    .with_max_attempts(confirmation_depth as usize),
            )
            .await
            .map_err(|e| {
                format!(
                    "timeout waiting for {confirmation_depth} confirmations: {}",
                    e.message()
                )
            })?;
        }

        tracing::info!(
            target: "world_id_gateway::batcher",
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
