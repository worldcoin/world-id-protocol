//! Operation Pool with lifecycle hooks.
//!
//! The `OpPool` manages the complete lifecycle of operations from ingress to finalization,
//! with automatic status updates at each stage via hooks.
//!
//! # Lifecycle Stages
//!
//! ```text
//! Received → Validated → Simulated → Batched → Included → Finalized
//!     ↓          ↓           ↓          ↓          ↓
//!   Failed    Failed     Failed     Failed     Failed
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! let pool = OpPool::builder()
//!     .with_hooks(hooks)
//!     .with_nonce_tracker(tracker)
//!     .build();
//!
//! // Operations are validated on entry
//! pool.submit(op).await?;
//!
//! // Take validated ops for batching
//! let ops = pool.take_batch(10);
//! ```

use crate::batcher::order::{NonceTracker, OrderingPolicy};
use crate::batcher::status_batcher::{StatusBatcher, StatusUpdate};
use crate::batcher::types::{OpEnvelopeInner, Operation};
use alloy::primitives::U256;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;
use world_id_core::types::{GatewayErrorCode, GatewayRequestState};

// ============================================================================
// Lifecycle Hooks
// ============================================================================

/// Lifecycle stage for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStage {
    /// Operation received but not yet validated.
    Received,
    /// Fast validation passed.
    Validated,
    /// Simulation completed successfully.
    Simulated,
    /// Added to a batch for submission.
    Batched,
    /// Included in a submitted transaction.
    Submitted,
    /// Transaction confirmed on-chain.
    Included,
    /// Operation failed at some stage.
    Failed,
}

impl LifecycleStage {
    /// Convert to `GatewayRequestState`.
    pub fn to_request_state(&self) -> GatewayRequestState {
        match self {
            Self::Received => GatewayRequestState::Queued,
            Self::Validated => GatewayRequestState::Queued,
            Self::Simulated => GatewayRequestState::Queued,
            Self::Batched => GatewayRequestState::Batching,
            Self::Submitted => GatewayRequestState::Submitted {
                tx_hash: String::new(),
            },
            Self::Included => GatewayRequestState::Finalized {
                tx_hash: String::new(),
            },
            Self::Failed => GatewayRequestState::failed("Operation failed", None),
        }
    }
}

/// Failure information for operations that fail.
#[derive(Debug, Clone)]
pub struct FailureInfo {
    pub stage: LifecycleStage,
    pub reason: String,
    pub error_code: Option<GatewayErrorCode>,
}

/// Hooks called at each lifecycle stage.
///
/// Implement this trait to receive callbacks when operations transition between stages.
/// The default implementation is a no-op.
pub trait PoolHooks: Send + Sync + 'static {
    /// Called when an operation is received.
    fn on_received(&self, _op_id: Uuid, _op: &Operation) {}

    /// Called when an operation passes fast validation.
    fn on_validated(&self, _op_id: Uuid) {}

    /// Called when an operation passes simulation.
    fn on_simulated(&self, _op_id: Uuid, _gas_estimate: u64) {}

    /// Called when an operation is added to a batch.
    fn on_batched(&self, _op_id: Uuid, _batch_id: Uuid) {}

    /// Called when a batch is included in a transaction.
    fn on_submitted(&self, _op_id: Uuid, _tx_hash: &str) {}

    /// Called when an operation is finalized on-chain.
    fn on_included(&self, _op_id: Uuid, _tx_hash: &str) {}

    /// Called when an operation fails at any stage.
    fn on_failed(&self, _op_id: Uuid, _failure: &FailureInfo) {}
}

/// Default no-op hooks.
pub struct NoopHooks;
impl PoolHooks for NoopHooks {}

/// Implement PoolHooks for Arc<H> to allow shared ownership.
impl<H: PoolHooks> PoolHooks for Arc<H> {
    fn on_received(&self, op_id: Uuid, op: &Operation) {
        (**self).on_received(op_id, op)
    }

    fn on_validated(&self, op_id: Uuid) {
        (**self).on_validated(op_id)
    }

    fn on_simulated(&self, op_id: Uuid, gas_estimate: u64) {
        (**self).on_simulated(op_id, gas_estimate)
    }

    fn on_batched(&self, op_id: Uuid, batch_id: Uuid) {
        (**self).on_batched(op_id, batch_id)
    }

    fn on_submitted(&self, op_id: Uuid, tx_hash: &str) {
        (**self).on_submitted(op_id, tx_hash)
    }

    fn on_included(&self, op_id: Uuid, tx_hash: &str) {
        (**self).on_included(op_id, tx_hash)
    }

    fn on_failed(&self, op_id: Uuid, failure: &FailureInfo) {
        (**self).on_failed(op_id, failure)
    }
}

/// Hooks that forward to a `StatusBatcher`.
#[derive(Clone)]
pub struct StatusBatcherHooks {
    batcher: StatusBatcher,
}

impl StatusBatcherHooks {
    pub fn new(batcher: StatusBatcher) -> Self {
        Self { batcher }
    }
}

impl PoolHooks for StatusBatcherHooks {
    fn on_received(&self, op_id: Uuid, _op: &Operation) {
        self.batcher.push(StatusUpdate::new(
            op_id.to_string(),
            GatewayRequestState::Queued,
        ));
    }

    fn on_batched(&self, op_id: Uuid, _batch_id: Uuid) {
        self.batcher.push(StatusUpdate::new(
            op_id.to_string(),
            GatewayRequestState::Batching,
        ));
    }

    fn on_submitted(&self, op_id: Uuid, tx_hash: &str) {
        self.batcher.push(StatusUpdate::new(
            op_id.to_string(),
            GatewayRequestState::Submitted {
                tx_hash: tx_hash.to_string(),
            },
        ));
    }

    fn on_included(&self, op_id: Uuid, tx_hash: &str) {
        self.batcher.push(StatusUpdate::new(
            op_id.to_string(),
            GatewayRequestState::Finalized {
                tx_hash: tx_hash.to_string(),
            },
        ));
    }

    fn on_failed(&self, op_id: Uuid, failure: &FailureInfo) {
        self.batcher.push(StatusUpdate::new(
            op_id.to_string(),
            GatewayRequestState::failed(&failure.reason, failure.error_code.clone()),
        ));
        tracing::debug!(
            op_id = %op_id,
            stage = ?failure.stage,
            reason = %failure.reason,
            error_code = ?failure.error_code,
            "op.failed"
        );
    }
}

// ============================================================================
// Pool Entry
// ============================================================================

/// An operation entry in the pool with lifecycle state.
#[derive(Debug)]
pub struct PoolEntry {
    /// The operation envelope.
    pub inner: OpEnvelopeInner,
    /// Current lifecycle stage.
    pub stage: LifecycleStage,
    /// When the operation entered this stage.
    pub stage_entered_at: Instant,
    /// Gas estimate from simulation (if simulated).
    pub gas_estimate: Option<u64>,
    /// Batch ID (if batched).
    pub batch_id: Option<Uuid>,
}

impl PoolEntry {
    pub fn new(inner: OpEnvelopeInner) -> Self {
        Self {
            inner,
            stage: LifecycleStage::Received,
            stage_entered_at: Instant::now(),
            gas_estimate: None,
            batch_id: None,
        }
    }

    pub fn id(&self) -> Uuid {
        self.inner.id
    }

    pub fn transition(&mut self, stage: LifecycleStage) {
        self.stage = stage;
        self.stage_entered_at = Instant::now();
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Validation error for operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolValidationError {
    #[error("Invalid signature length: expected 65, got {0}")]
    InvalidSignatureLength(usize),

    #[error("Nonce too low: expected >= {expected}, got {actual}")]
    NonceTooLow { expected: U256, actual: U256 },

    #[error("Operation has gap in nonce sequence")]
    NonceGap,

    #[error("Pool is full")]
    PoolFull,
}

impl PoolValidationError {
    pub fn to_error_code(&self) -> GatewayErrorCode {
        match self {
            Self::InvalidSignatureLength(_) => GatewayErrorCode::BadRequest,
            Self::NonceTooLow { .. } => GatewayErrorCode::BadRequest,
            Self::NonceGap => GatewayErrorCode::BadRequest,
            Self::PoolFull => GatewayErrorCode::BatcherUnavailable,
        }
    }
}

// ============================================================================
// Operation Pool
// ============================================================================

/// Configuration for the operation pool.
#[derive(Debug, Clone)]
pub struct OpPoolConfig {
    /// Maximum number of operations in the pool.
    pub max_size: usize,
    /// Whether to validate nonces on entry.
    pub validate_nonces: bool,
}

impl Default for OpPoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10_000,
            validate_nonces: false, // Disabled by default; nonce tracking across batches is complex
        }
    }
}

/// Thread-safe operation pool with lifecycle hooks.
///
/// The pool maintains:
/// - Operations indexed by ID
/// - Nonce tracking per signer
/// - A priority queue for batch selection
/// - Lifecycle hooks for status updates
///
/// The `P` type parameter is a policy wrapper (e.g., `GreedyCreateFirst`)
/// that implements `PolicyWrapper` and determines the ordering of operations.
pub struct OpPool<P: OrderingPolicy, H: PoolHooks = NoopHooks> {
    /// Configuration.
    config: OpPoolConfig,
    /// Operations indexed by ID.
    entries: RwLock<HashMap<Uuid, PoolEntry>>,
    /// Priority queue for validated operations.
    ready_queue: RwLock<BinaryHeap<P>>,
    /// Nonce tracker for validation (uses std Mutex for sync access).
    nonce_tracker: Mutex<NonceTracker>,
    /// Lifecycle hooks.
    hooks: Arc<H>,
}

impl<P: OrderingPolicy> OpPool<P, NoopHooks> {
    /// Create a new pool with default hooks.
    pub fn new(config: OpPoolConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            ready_queue: RwLock::new(BinaryHeap::new()),
            nonce_tracker: Mutex::new(NonceTracker::new()),
            hooks: Arc::new(NoopHooks),
        }
    }
}

impl<P: OrderingPolicy, H: PoolHooks> OpPool<P, H> {
    /// Create a new pool with custom hooks.
    pub fn with_hooks(config: OpPoolConfig, hooks: H) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            ready_queue: RwLock::new(BinaryHeap::new()),
            nonce_tracker: Mutex::new(NonceTracker::new()),
            hooks: Arc::new(hooks),
        }
    }

    /// Submit an operation to the pool.
    ///
    /// The operation is validated on entry. If validation passes, it's added
    /// to the ready queue for batching.
    pub async fn submit(&self, op: OpEnvelopeInner) -> Result<Uuid, PoolValidationError> {
        let op_id = op.id;

        // Check pool capacity
        {
            let entries = self.entries.read().await;
            if entries.len() >= self.config.max_size {
                return Err(PoolValidationError::PoolFull);
            }
        }

        // Fire received hook
        self.hooks.on_received(op_id, &op.op);

        // Fast validation
        self.fast_validate(&op)?;

        // Create pool entry
        let mut entry = PoolEntry::new(op.clone());
        entry.transition(LifecycleStage::Validated);

        // Fire validated hook
        self.hooks.on_validated(op_id);

        // Mark pending in nonce tracker
        self.nonce_tracker.lock().unwrap().mark_pending(&op);

        // Add to entries
        {
            let mut entries = self.entries.write().await;
            entries.insert(op_id, entry);
        }

        // Add to ready queue
        {
            let mut queue = self.ready_queue.write().await;
            queue.push(P::new(op));
        }

        tracing::debug!(op_id = %op_id, "pool.op_submitted");

        Ok(op_id)
    }

    /// Fast validation (synchronous, non-blocking).
    fn fast_validate(&self, op: &OpEnvelopeInner) -> Result<(), PoolValidationError> {
        // Validate signature length
        let sig_len = match &op.op {
            Operation::CreateAccount(data) => data.signature.len(),
            Operation::InsertAuthenticator(data) => data.signature.len(),
            Operation::UpdateAuthenticator(data) => data.signature.len(),
            Operation::RemoveAuthenticator(data) => data.signature.len(),
            Operation::RecoverAccount(data) => data.signature.len(),
        };

        if sig_len != 65 {
            return Err(PoolValidationError::InvalidSignatureLength(sig_len));
        }

        // Validate nonce if enabled
        if self.config.validate_nonces {
            let tracker = self.nonce_tracker.lock().unwrap();
            // Check if op is stale (nonce already confirmed)
            if tracker.is_stale(op) {
                let expected = tracker.next_expected(&op.signer);
                return Err(PoolValidationError::NonceTooLow {
                    expected,
                    actual: op.nonce,
                });
            }

            // Check if there's a gap in the nonce sequence
            if tracker.has_gap(op) {
                return Err(PoolValidationError::NonceGap);
            }
        }

        Ok(())
    }

    /// Mark an operation as simulated with a gas estimate.
    pub async fn mark_simulated(&self, op_id: Uuid, gas_estimate: u64) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(&op_id) {
            entry.transition(LifecycleStage::Simulated);
            entry.gas_estimate = Some(gas_estimate);
            self.hooks.on_simulated(op_id, gas_estimate);
        }
    }

    /// Mark operations as batched.
    pub async fn mark_batched(&self, op_ids: &[Uuid], batch_id: Uuid) {
        let mut entries = self.entries.write().await;
        for op_id in op_ids {
            if let Some(entry) = entries.get_mut(op_id) {
                entry.transition(LifecycleStage::Batched);
                entry.batch_id = Some(batch_id);
                self.hooks.on_batched(*op_id, batch_id);
            }
        }
    }

    /// Mark operations as submitted in a transaction.
    pub async fn mark_submitted(&self, op_ids: &[Uuid], tx_hash: &str) {
        let mut entries = self.entries.write().await;
        for op_id in op_ids {
            if let Some(entry) = entries.get_mut(op_id) {
                entry.transition(LifecycleStage::Submitted);
                self.hooks.on_submitted(*op_id, tx_hash);
            }
        }
    }

    /// Mark operations as included and remove from pool.
    pub async fn mark_included(&self, op_ids: &[Uuid], tx_hash: &str) {
        let mut entries = self.entries.write().await;
        let mut tracker = self.nonce_tracker.lock().unwrap();
        for op_id in op_ids {
            if let Some(entry) = entries.remove(op_id) {
                // Unmark from nonce tracker
                tracker.unmark_pending(&entry.inner);
                self.hooks.on_included(*op_id, tx_hash);
            }
        }
    }

    /// Mark an operation as failed and remove from pool.
    pub async fn mark_failed(&self, op_id: Uuid, stage: LifecycleStage, reason: String) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.remove(&op_id) {
            // Unmark from nonce tracker
            self.nonce_tracker
                .lock()
                .unwrap()
                .unmark_pending(&entry.inner);

            let failure = FailureInfo {
                stage,
                reason,
                error_code: None,
            };
            self.hooks.on_failed(op_id, &failure);
        }
    }

    /// Mark an operation as failed with an error code.
    pub async fn mark_failed_with_code(
        &self,
        op_id: Uuid,
        stage: LifecycleStage,
        reason: String,
        error_code: GatewayErrorCode,
    ) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.remove(&op_id) {
            // Unmark from nonce tracker
            self.nonce_tracker
                .lock()
                .unwrap()
                .unmark_pending(&entry.inner);

            let failure = FailureInfo {
                stage,
                reason,
                error_code: Some(error_code),
            };
            self.hooks.on_failed(op_id, &failure);
        }
    }

    /// Take operations from the ready queue for batching.
    ///
    /// Returns up to `max_ops` operations in priority order.
    pub async fn take_batch(&self, max_ops: usize) -> Vec<OpEnvelopeInner> {
        let mut queue = self.ready_queue.write().await;
        let mut ops = Vec::with_capacity(max_ops.min(queue.len()));

        while ops.len() < max_ops {
            if let Some(envelope) = queue.pop() {
                ops.push(envelope.into_inner());
            } else {
                break;
            }
        }

        ops
    }

    /// Get the number of operations in the pool.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if the pool is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Get the number of operations ready for batching.
    pub async fn ready_count(&self) -> usize {
        self.ready_queue.read().await.len()
    }

    /// Get an operation by ID.
    pub async fn get(&self, op_id: Uuid) -> Option<PoolEntry> {
        let entries = self.entries.read().await;
        entries.get(&op_id).map(|e| PoolEntry {
            inner: e.inner.clone(),
            stage: e.stage,
            stage_entered_at: e.stage_entered_at,
            gas_estimate: e.gas_estimate,
            batch_id: e.batch_id,
        })
    }

    /// Get a lock guard to the nonce tracker.
    pub fn nonce_tracker(&self) -> std::sync::MutexGuard<'_, NonceTracker> {
        self.nonce_tracker.lock().unwrap()
    }

    /// Clear all operations from the pool.
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        let mut queue = self.ready_queue.write().await;
        let mut tracker = self.nonce_tracker.lock().unwrap();

        for (op_id, entry) in entries.drain() {
            tracker.unmark_pending(&entry.inner);
            let failure = FailureInfo {
                stage: entry.stage,
                reason: "Pool cleared".to_string(),
                error_code: None,
            };
            self.hooks.on_failed(op_id, &failure);
        }

        queue.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher::order::SignupFifoOrdering;
    use crate::batcher::types::CreateAccountOp;
    use alloy::primitives::{Address, Bytes};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    fn mock_op(signer: Address, nonce: u64) -> OpEnvelopeInner {
        OpEnvelopeInner {
            id: Uuid::new_v4(),
            op: Operation::CreateAccount(CreateAccountOp {
                initial_commitment: U256::from(1),
                signature: Bytes::from(vec![0u8; 65]),
            }),
            received_at: Instant::now().into(),
            signer,
            nonce: U256::from(nonce),
        }
    }

    struct CountingHooks {
        received: AtomicU64,
        validated: AtomicU64,
        failed: AtomicU64,
    }

    impl CountingHooks {
        fn new() -> Self {
            Self {
                received: AtomicU64::new(0),
                validated: AtomicU64::new(0),
                failed: AtomicU64::new(0),
            }
        }
    }

    impl PoolHooks for CountingHooks {
        fn on_received(&self, _op_id: Uuid, _op: &Operation) {
            self.received.fetch_add(1, AtomicOrdering::SeqCst);
        }

        fn on_validated(&self, _op_id: Uuid) {
            self.validated.fetch_add(1, AtomicOrdering::SeqCst);
        }

        fn on_failed(&self, _op_id: Uuid, _failure: &FailureInfo) {
            self.failed.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_submit_and_hooks() {
        let hooks = CountingHooks::new();
        let pool = OpPool::<SignupFifoOrdering<OpEnvelopeInner>, _>::with_hooks(
            OpPoolConfig::default(),
            hooks,
        );

        let op = mock_op(Address::ZERO, 0);
        let result = pool.submit(op).await;

        assert!(result.is_ok());
        // Hooks are wrapped in Arc, so we access through the pool
        assert_eq!(pool.len().await, 1);
        assert_eq!(pool.ready_count().await, 1);
    }

    #[tokio::test]
    async fn test_invalid_signature_length() {
        let pool = OpPool::<SignupFifoOrdering<OpEnvelopeInner>>::new(OpPoolConfig::default());

        let mut op = mock_op(Address::ZERO, 0);
        // Set invalid signature length
        if let Operation::CreateAccount(ref mut create) = op.op {
            create.signature = Bytes::from(vec![0u8; 32]); // Wrong length
        }

        let result = pool.submit(op).await;
        assert!(matches!(
            result,
            Err(PoolValidationError::InvalidSignatureLength(32))
        ));
    }

    #[tokio::test]
    async fn test_take_batch() {
        let pool = OpPool::<SignupFifoOrdering<OpEnvelopeInner>>::new(OpPoolConfig::default());

        // Submit 5 operations with different signers
        for i in 0..5 {
            let mut addr_bytes = [0u8; 20];
            addr_bytes[0] = i;
            let op = mock_op(Address::from(addr_bytes), 0);
            pool.submit(op).await.unwrap();
        }

        assert_eq!(pool.ready_count().await, 5);

        // Take 3
        let batch = pool.take_batch(3).await;
        assert_eq!(batch.len(), 3);
        assert_eq!(pool.ready_count().await, 2);

        // Take remaining
        let batch = pool.take_batch(10).await;
        assert_eq!(batch.len(), 2);
        assert_eq!(pool.ready_count().await, 0);
    }

    #[tokio::test]
    async fn test_lifecycle_transitions() {
        let pool = OpPool::<SignupFifoOrdering<OpEnvelopeInner>>::new(OpPoolConfig::default());

        let op = mock_op(Address::ZERO, 0);
        let op_id = pool.submit(op).await.unwrap();
        let batch_id = Uuid::new_v4();

        // Check initial state
        let entry = pool.get(op_id).await.unwrap();
        assert_eq!(entry.stage, LifecycleStage::Validated);

        // Mark simulated
        pool.mark_simulated(op_id, 100_000).await;
        let entry = pool.get(op_id).await.unwrap();
        assert_eq!(entry.stage, LifecycleStage::Simulated);
        assert_eq!(entry.gas_estimate, Some(100_000));

        // Mark batched
        pool.mark_batched(&[op_id], batch_id).await;
        let entry = pool.get(op_id).await.unwrap();
        assert_eq!(entry.stage, LifecycleStage::Batched);
        assert_eq!(entry.batch_id, Some(batch_id));

        // Mark submitted
        pool.mark_submitted(&[op_id], "0x123").await;
        let entry = pool.get(op_id).await.unwrap();
        assert_eq!(entry.stage, LifecycleStage::Submitted);

        // Mark included (removes from pool)
        pool.mark_included(&[op_id], "0x123").await;
        assert!(pool.get(op_id).await.is_none());
        assert_eq!(pool.len().await, 0);
    }
}
