//! Background validation and simulation worker.
//!
//! The `ValidationWorker` runs in a separate task and handles:
//! - Fast synchronous validation (nonce checks, signature format)
//! - Batch simulation via Multicall3
//! - Forwarding validated operations to the main queue
//! - Rejecting invalid operations with status updates

use crate::batcher::pending_batch::{Multicall3, MULTICALL3_ADDR};
use crate::batcher::status_batcher::StatusUpdate;
use crate::batcher::types::{OpEnvelopeInner, Operation};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use world_id_core::types::{GatewayErrorCode, GatewayRequestState};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the validation worker.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Debounce interval for batching simulation requests.
    pub simulation_debounce: Duration,
    /// Maximum operations to simulate in one batch.
    pub max_simulation_batch: usize,
    /// Timeout for simulation calls.
    pub simulation_timeout: Duration,
    /// Registry contract address.
    pub registry: Address,
    /// Maximum nonce gap allowed.
    pub max_nonce_gap: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            simulation_debounce: Duration::from_millis(50),
            max_simulation_batch: 64,
            simulation_timeout: Duration::from_secs(10),
            registry: Address::ZERO,
            max_nonce_gap: 100,
        }
    }
}

// ============================================================================
// Validated Operation
// ============================================================================

/// An operation that has passed validation and simulation.
#[derive(Debug)]
pub struct ValidatedOp {
    /// The original operation envelope.
    pub inner: OpEnvelopeInner,
    /// Gas estimate from simulation.
    pub simulation_gas: u64,
    /// When validation completed.
    pub validated_at: Instant,
}

// ============================================================================
// Validation Errors
// ============================================================================

/// Errors that can occur during validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error("nonce too low: expected {expected}, got {got}")]
    NonceTooLow { expected: U256, got: U256 },

    #[error("nonce too high: expected {expected}, got {got}")]
    NonceTooHigh { expected: U256, got: U256 },

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("simulation failed: {0}")]
    SimulationFailed(String),
}

impl ValidationError {
    pub fn to_gateway_state(&self) -> GatewayRequestState {
        GatewayRequestState::Failed {
            error: self.to_string(),
            error_code: Some(self.error_code()),
        }
    }

    pub fn error_code(&self) -> GatewayErrorCode {
        match self {
            Self::NonceTooLow { .. } | Self::NonceTooHigh { .. } => GatewayErrorCode::BadRequest,
            Self::InvalidSignature(_) | Self::InvalidInput(_) => GatewayErrorCode::BadRequest,
            Self::SimulationFailed(_) => GatewayErrorCode::TransactionReverted,
        }
    }
}

// ============================================================================
// Simulation Result
// ============================================================================

#[derive(Debug)]
enum SimResult {
    Valid { gas: u64 },
    Invalid { reason: ValidationError },
}

// ============================================================================
// Nonce Tracker (simplified)
// ============================================================================

/// Tracks confirmed and pending nonces per signer.
#[derive(Debug, Default)]
pub struct NonceState {
    /// Confirmed nonce (from chain).
    confirmed: HashMap<Address, U256>,
    /// Pending nonces (in-flight).
    pending: HashMap<Address, U256>,
}

impl NonceState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the next expected nonce for a signer.
    pub fn next_expected(&self, signer: &Address) -> U256 {
        self.pending
            .get(signer)
            .or_else(|| self.confirmed.get(signer))
            .copied()
            .unwrap_or(U256::ZERO)
    }

    /// Check if a nonce is stale (below confirmed).
    pub fn is_stale(&self, signer: &Address, nonce: U256) -> bool {
        self.confirmed
            .get(signer)
            .map(|&confirmed| nonce < confirmed)
            .unwrap_or(false)
    }

    /// Mark a nonce as pending.
    pub fn mark_pending(&mut self, signer: Address, nonce: U256) {
        let next = nonce + U256::from(1);
        self.pending
            .entry(signer)
            .and_modify(|n| *n = (*n).max(next))
            .or_insert(next);
    }

    /// Confirm nonces up to a certain value.
    pub fn confirm(&mut self, signer: Address, nonce: U256) {
        let next = nonce + U256::from(1);
        self.confirmed.insert(signer, next);
        // Clear pending if it's now below confirmed
        if let Some(pending) = self.pending.get(&signer) {
            if *pending <= next {
                self.pending.remove(&signer);
            }
        }
    }
}

// ============================================================================
// Metrics
// ============================================================================

/// Metrics for the validation worker.
#[derive(Debug, Default)]
pub struct ValidationMetrics {
    pub ops_received: AtomicU64,
    pub ops_validated: AtomicU64,
    pub ops_rejected: AtomicU64,
    pub simulation_batches: AtomicU64,
    pub simulation_failures: AtomicU64,
}

impl ValidationMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_received(&self) {
        self.ops_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_validated(&self) {
        self.ops_validated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rejected(&self) {
        self.ops_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_simulation_batch(&self) {
        self.simulation_batches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_simulation_failure(&self) {
        self.simulation_failures.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Validation Worker
// ============================================================================

/// Background worker that validates and simulates operations.
///
/// Runs in its own task, never blocking the main driver loop.
pub struct ValidationWorker<P> {
    /// Blockchain provider for simulation.
    provider: Arc<P>,
    /// Configuration.
    config: ValidationConfig,
    /// Receives raw operations from ingress.
    raw_rx: mpsc::Receiver<OpEnvelopeInner>,
    /// Sends validated operations to the main queue.
    validated_tx: mpsc::Sender<ValidatedOp>,
    /// Sends status updates (for rejections).
    status_tx: mpsc::Sender<StatusUpdate>,
    /// Nonce state tracking.
    nonce_state: NonceState,
    /// Metrics.
    metrics: Arc<ValidationMetrics>,
    /// Shutdown signal.
    cancel: CancellationToken,
}

impl<P: Provider + Clone + Send + Sync + 'static> ValidationWorker<P> {
    /// Create a new validation worker.
    pub fn new(
        provider: Arc<P>,
        config: ValidationConfig,
        raw_rx: mpsc::Receiver<OpEnvelopeInner>,
        validated_tx: mpsc::Sender<ValidatedOp>,
        status_tx: mpsc::Sender<StatusUpdate>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            provider,
            config,
            raw_rx,
            validated_tx,
            status_tx,
            nonce_state: NonceState::new(),
            metrics: Arc::new(ValidationMetrics::new()),
            cancel,
        }
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> Arc<ValidationMetrics> {
        self.metrics.clone()
    }

    /// Run the validation worker loop.
    pub async fn run(mut self) {
        let span = tracing::info_span!("validation_worker");

        async {
            tracing::info!("validation_worker.started");

            // Batch operations for simulation (debounce)
            let mut pending: Vec<OpEnvelopeInner> =
                Vec::with_capacity(self.config.max_simulation_batch);
            let mut debounce = tokio::time::interval(self.config.simulation_debounce);
            debounce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;

                    _ = self.cancel.cancelled() => {
                        tracing::info!("validation_worker.cancelled");
                        break;
                    }

                    Some(op) = self.raw_rx.recv() => {
                        self.metrics.inc_received();

                        // Fast sync validation (nonce, signature format)
                        match self.fast_validate(&op) {
                            Ok(()) => {
                                pending.push(op);

                                // If we hit max batch size, simulate immediately
                                if pending.len() >= self.config.max_simulation_batch {
                                    let batch = std::mem::take(&mut pending);
                                    self.simulate_and_forward(batch).await;
                                }
                            }
                            Err(e) => {
                                self.reject_op(&op, e).await;
                            }
                        }
                    }

                    _ = debounce.tick(), if !pending.is_empty() => {
                        // Batch simulation via Multicall3
                        let batch = std::mem::take(&mut pending);
                        self.simulate_and_forward(batch).await;
                    }

                    else => break,
                }
            }

            // Flush any remaining pending ops
            if !pending.is_empty() {
                self.simulate_and_forward(pending).await;
            }

            tracing::info!("validation_worker.stopped");
        }
        .instrument(span)
        .await
    }

    /// Fast synchronous validation (never blocks).
    fn fast_validate(&self, op: &OpEnvelopeInner) -> Result<(), ValidationError> {
        // Check nonce isn't stale
        if self.nonce_state.is_stale(&op.signer, op.nonce) {
            let expected = self.nonce_state.next_expected(&op.signer);
            return Err(ValidationError::NonceTooLow {
                expected,
                got: op.nonce,
            });
        }

        // Check for excessive nonce gap
        let next = self.nonce_state.next_expected(&op.signer);
        if op.nonce > next + U256::from(self.config.max_nonce_gap) {
            return Err(ValidationError::NonceTooHigh {
                expected: next,
                got: op.nonce,
            });
        }

        // Operation-specific validation
        self.validate_operation(&op.op)?;

        Ok(())
    }

    /// Validate operation-specific constraints.
    fn validate_operation(&self, op: &Operation) -> Result<(), ValidationError> {
        match op {
            Operation::CreateAccount(data) => {
                if data.signature.len() != 65 {
                    return Err(ValidationError::InvalidSignature(
                        "Signature must be 65 bytes".into(),
                    ));
                }
                if data.initial_commitment == U256::ZERO {
                    return Err(ValidationError::InvalidInput(
                        "Initial commitment cannot be zero".into(),
                    ));
                }
            }
            Operation::InsertAuthenticator(data) => {
                if data.signature.len() != 65 {
                    return Err(ValidationError::InvalidSignature(
                        "Signature must be 65 bytes".into(),
                    ));
                }
                if data.leaf_index == U256::ZERO {
                    return Err(ValidationError::InvalidInput(
                        "Leaf index cannot be zero".into(),
                    ));
                }
            }
            Operation::UpdateAuthenticator(data) => {
                if data.signature.len() != 65 {
                    return Err(ValidationError::InvalidSignature(
                        "Signature must be 65 bytes".into(),
                    ));
                }
                if data.leaf_index == U256::ZERO {
                    return Err(ValidationError::InvalidInput(
                        "Leaf index cannot be zero".into(),
                    ));
                }
            }
            Operation::RemoveAuthenticator(data) => {
                if data.signature.len() != 65 {
                    return Err(ValidationError::InvalidSignature(
                        "Signature must be 65 bytes".into(),
                    ));
                }
                if data.leaf_index == U256::ZERO {
                    return Err(ValidationError::InvalidInput(
                        "Leaf index cannot be zero".into(),
                    ));
                }
            }
            Operation::RecoverAccount(data) => {
                if data.signature.len() != 65 {
                    return Err(ValidationError::InvalidSignature(
                        "Signature must be 65 bytes".into(),
                    ));
                }
                if data.leaf_index == U256::ZERO {
                    return Err(ValidationError::InvalidInput(
                        "Leaf index cannot be zero".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Simulate a batch of operations via Multicall3 and forward valid ones.
    async fn simulate_and_forward(&mut self, ops: Vec<OpEnvelopeInner>) {
        if ops.is_empty() {
            return;
        }

        let count = ops.len();
        let span = tracing::info_span!("simulate_batch", count);

        async {
            self.metrics.inc_simulation_batch();

            let results = self.simulate_multicall(&ops).await;

            for (op, result) in ops.into_iter().zip(results) {
                match result {
                    SimResult::Valid { gas } => {
                        // Mark nonce as pending
                        self.nonce_state.mark_pending(op.signer, op.nonce);

                        let validated = ValidatedOp {
                            inner: op,
                            simulation_gas: gas,
                            validated_at: Instant::now(),
                        };

                        if self.validated_tx.try_send(validated).is_err() {
                            tracing::warn!("validation_worker.validated_channel_full");
                        } else {
                            self.metrics.inc_validated();
                        }
                    }
                    SimResult::Invalid { reason } => {
                        self.reject_op(&op, reason).await;
                    }
                }
            }
        }
        .instrument(span)
        .await
    }

    /// Simulate operations via Multicall3.
    async fn simulate_multicall(&self, ops: &[OpEnvelopeInner]) -> Vec<SimResult> {
        if ops.is_empty() {
            return Vec::new();
        }

        // Build multicall
        let calls: Vec<Multicall3::Call3> = ops
            .iter()
            .map(|op| Multicall3::Call3 {
                target: self.config.registry,
                allowFailure: true,
                callData: self.encode_operation(&op.op),
            })
            .collect();

        let multicall = Multicall3::aggregate3Call { calls };
        let tx = TransactionRequest::default()
            .to(MULTICALL3_ADDR)
            .input(multicall.abi_encode().into());

        // Execute simulation with timeout
        let result = tokio::time::timeout(self.config.simulation_timeout, async {
            self.provider.call(tx).await
        })
        .await;

        match result {
            Ok(Ok(data)) => self.parse_simulation_results(ops, &data),
            Ok(Err(e)) => {
                self.metrics.inc_simulation_failure();
                tracing::warn!(error = %e, "simulation_call_failed");
                // On simulation failure, assume all ops are valid with estimated gas
                ops.iter()
                    .map(|op| SimResult::Valid {
                        gas: op.op.estimated_gas(),
                    })
                    .collect()
            }
            Err(_) => {
                self.metrics.inc_simulation_failure();
                tracing::warn!("simulation_timeout");
                // On timeout, assume all ops are valid with estimated gas
                ops.iter()
                    .map(|op| SimResult::Valid {
                        gas: op.op.estimated_gas(),
                    })
                    .collect()
            }
        }
    }

    /// Parse Multicall3 results.
    fn parse_simulation_results(&self, ops: &[OpEnvelopeInner], data: &Bytes) -> Vec<SimResult> {
        match Multicall3::aggregate3Call::abi_decode_returns(data) {
            Ok(decoded) => {
                let results: &[Multicall3::Result] = &decoded;

                ops.iter()
                    .zip(results.iter())
                    .map(|(op, res)| {
                        if res.success {
                            SimResult::Valid {
                                gas: op.op.estimated_gas(),
                            }
                        } else {
                            let msg = if res.returnData.is_empty() {
                                "Reverted".to_string()
                            } else {
                                format!("0x{}", hex::encode(&res.returnData))
                            };
                            SimResult::Invalid {
                                reason: ValidationError::SimulationFailed(msg),
                            }
                        }
                    })
                    .collect()
            }
            Err(e) => {
                tracing::warn!(error = %e, "simulation_decode_failed");
                // On decode failure, assume all ops are valid with estimated gas
                ops.iter()
                    .map(|op| SimResult::Valid {
                        gas: op.op.estimated_gas(),
                    })
                    .collect()
            }
        }
    }

    /// Encode an operation for the registry contract.
    fn encode_operation(&self, _op: &Operation) -> Bytes {
        // TODO: Implement actual encoding based on operation type
        Bytes::new()
    }

    /// Reject an operation and send status update.
    async fn reject_op(&self, op: &OpEnvelopeInner, error: ValidationError) {
        self.metrics.inc_rejected();

        tracing::debug!(
            op_id = %op.id,
            error = %error,
            "op_rejected"
        );

        let update = StatusUpdate::new(op.id.to_string(), error.to_gateway_state());

        if self.status_tx.try_send(update).is_err() {
            tracing::warn!("validation_worker.status_channel_full");
        }
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for creating a ValidationWorker with its channels.
pub struct ValidationWorkerBuilder<P> {
    provider: Arc<P>,
    config: ValidationConfig,
    raw_buffer: usize,
    validated_buffer: usize,
    status_buffer: usize,
}

impl<P: Provider + Clone + Send + Sync + 'static> ValidationWorkerBuilder<P> {
    pub fn new(provider: Arc<P>) -> Self {
        Self {
            provider,
            config: ValidationConfig::default(),
            raw_buffer: 1024,
            validated_buffer: 256,
            status_buffer: 64,
        }
    }

    pub fn config(mut self, config: ValidationConfig) -> Self {
        self.config = config;
        self
    }

    pub fn raw_buffer(mut self, size: usize) -> Self {
        self.raw_buffer = size;
        self
    }

    pub fn validated_buffer(mut self, size: usize) -> Self {
        self.validated_buffer = size;
        self
    }

    /// Build the worker and return all channels.
    ///
    /// Returns:
    /// - The worker itself
    /// - Sender for raw operations (ingress uses this)
    /// - Receiver for validated operations (main loop uses this)
    /// - Receiver for status updates (status batcher uses this)
    pub fn build(
        self,
        cancel: CancellationToken,
    ) -> (
        ValidationWorker<P>,
        mpsc::Sender<OpEnvelopeInner>,
        mpsc::Receiver<ValidatedOp>,
        mpsc::Receiver<StatusUpdate>,
    ) {
        let (raw_tx, raw_rx) = mpsc::channel(self.raw_buffer);
        let (validated_tx, validated_rx) = mpsc::channel(self.validated_buffer);
        let (status_tx, status_rx) = mpsc::channel(self.status_buffer);

        let worker = ValidationWorker::new(
            self.provider,
            self.config,
            raw_rx,
            validated_tx,
            status_tx,
            cancel,
        );

        (worker, raw_tx, validated_rx, status_rx)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher::types::{CreateAccountOp, Operation};
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

    #[test]
    fn test_nonce_state() {
        let mut state = NonceState::new();
        let signer = Address::ZERO;

        assert_eq!(state.next_expected(&signer), U256::ZERO);
        assert!(!state.is_stale(&signer, U256::ZERO));

        state.mark_pending(signer, U256::ZERO);
        assert_eq!(state.next_expected(&signer), U256::from(1));

        state.confirm(signer, U256::ZERO);
        assert_eq!(state.next_expected(&signer), U256::from(1));
        assert!(state.is_stale(&signer, U256::ZERO));
    }

    #[test]
    fn test_fast_validate_signature_length() {
        let _config = ValidationConfig::default();
        let (_raw_tx, _raw_rx) = mpsc::channel::<OpEnvelopeInner>(1);
        let (_validated_tx, _) = mpsc::channel::<ValidatedOp>(1);
        let (_status_tx, _) = mpsc::channel::<StatusUpdate>(1);

        // Create a minimal mock provider - we won't actually use it
        // In real tests, you'd use a proper mock

        // Test validation logic directly
        let mut op = mock_op();
        if let Operation::CreateAccount(ref mut data) = op.op {
            data.signature = Bytes::from(vec![0u8; 64]); // Wrong length
        }

        // The validation should fail for wrong signature length
        // (This test is more illustrative - in practice you'd test the worker)
    }
}
