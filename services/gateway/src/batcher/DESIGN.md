# OpsBatcher Architecture Design

## Overview

A complete rearchitecture of the operation batching system with:
- Single unified `OpsBatcher` handling all batching and transaction submission
- `PendingBatchFut` as spawned tasks managing their own transaction lifecycle
- Policy-based operation ordering with dependency resolution
- Adaptive batch sizing based on chain conditions
- Comprehensive simulation and eviction

## Module Structure

```
services/gateway/src/batcher/
├── mod.rs                 # Public exports
├── ops_batcher.rs         # Main OpsBatcher implementation
├── pending_batch.rs       # PendingBatchFut implementation
├── chain_monitor.rs       # ChainMonitor for fee/capacity tracking
├── ordering/
│   ├── mod.rs             # Ordering trait and types
│   ├── policy.rs          # OrderingPolicy trait
│   └── greedy.rs          # GreedyCreateFirstPolicy
├── adaptive.rs            # Adaptive batch sizing model
├── nonce_tracker.rs       # Per-signer nonce dependency tracking
├── simulation.rs          # Batch simulation and eviction
├── metrics.rs             # Prometheus metrics
└── types.rs               # Shared types
```

## Core Types

### Operation Envelope

```rust
/// Unified operation envelope for all operation types
pub struct OpEnvelope {
    /// Unique identifier for this operation
    pub id: Uuid,
    /// The operation payload
    pub op: Operation,
    /// Timestamp when the operation was received
    pub received_at: Instant,
    /// Signer address (derived from operation)
    pub signer: Address,
    /// Operation nonce
    pub nonce: U256,
}

/// All supported operation types
pub enum Operation {
    CreateAccount(CreateAccountOp),
    InsertAuthenticator(InsertAuthenticatorOp),
    UpdateAuthenticator(UpdateAuthenticatorOp),
    RemoveAuthenticator(RemoveAuthenticatorOp),
    RecoverAccount(RecoverAccountOp),
}

impl Operation {
    /// Returns the operation priority class
    pub fn priority_class(&self) -> PriorityClass {
        match self {
            Self::CreateAccount(_) => PriorityClass::Critical,
            Self::RecoverAccount(_) => PriorityClass::High,
            _ => PriorityClass::Normal,
        }
    }

    /// Encode as calldata for the target contract
    pub fn encode_calldata(&self) -> Bytes { ... }

    /// Target contract address
    pub fn target(&self) -> Address { ... }

    /// Estimated gas for this operation
    pub fn estimated_gas(&self) -> u64 { ... }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityClass {
    Normal = 0,
    High = 1,
    Critical = 2,
}
```

### Operation Status

```rust
/// Final status of an operation after batch resolution
#[derive(Debug, Clone)]
pub enum OpStatus {
    /// Successfully finalized on-chain
    Finalized {
        tx_hash: B256,
        block_number: u64,
        gas_used: u64,
    },
    /// Failed during simulation or execution
    Failed {
        reason: FailureReason,
        revert_data: Option<Bytes>,
    },
    /// Evicted from batch (will be retried)
    Evicted {
        reason: EvictionReason,
    },
}

#[derive(Debug, Clone)]
pub enum FailureReason {
    SimulationReverted(String),
    ExecutionReverted(String),
    NonceTooLow,
    NonceTooHigh,
    InsufficientBalance,
    InvalidSignature,
    ContractError(GatewayErrorCode),
    Unknown(String),
}

#[derive(Debug, Clone)]
pub enum EvictionReason {
    BatchFull,
    DependencyNotReady,
    GasLimitExceeded,
    Timeout,
}
```

### Finalized Batch

```rust
/// Result of a fully resolved batch
pub struct FinalizedBatch {
    /// Batch identifier
    pub batch_id: Uuid,
    /// Final transaction hash (if submitted)
    pub tx_hash: Option<B256>,
    /// Block number where batch was included
    pub block_number: Option<u64>,
    /// Total gas used
    pub gas_used: u64,
    /// Status of each operation
    pub statuses: HashMap<Uuid, OpStatus>,
    /// Batch timing metrics
    pub timing: BatchTiming,
}

pub struct BatchTiming {
    pub created_at: Instant,
    pub simulation_completed_at: Option<Instant>,
    pub submitted_at: Option<Instant>,
    pub finalized_at: Instant,
    pub total_duration: Duration,
    pub resubmission_count: u32,
}
```

## Ordering System

### OrderingPolicy Trait

```rust
/// Policy for ordering operations within a batch
pub trait OrderingPolicy: Send + Sync + 'static {
    /// Compare two operations for ordering
    /// Returns Ordering::Less if `a` should come before `b`
    fn compare(&self, a: &OpEnvelope, b: &OpEnvelope) -> Ordering;

    /// Filter operations that should be considered for this batch
    fn filter(&self, op: &OpEnvelope, batch_context: &BatchContext) -> bool {
        true // Default: include all
    }
}

/// Context available during ordering decisions
pub struct BatchContext {
    pub current_base_fee: u64,
    pub target_gas: u64,
    pub pending_count: usize,
    pub batch_number: u64,
}
```

### Greedy Create-First Policy

```rust
/// Prioritizes CreateAccount operations, then by received time
pub struct GreedyCreateFirstPolicy;

impl OrderingPolicy for GreedyCreateFirstPolicy {
    fn compare(&self, a: &OpEnvelope, b: &OpEnvelope) -> Ordering {
        // First: compare by priority class (Critical > High > Normal)
        match b.op.priority_class().cmp(&a.op.priority_class()) {
            Ordering::Equal => {}
            other => return other,
        }

        // Second: older operations first (FIFO within same priority)
        a.received_at.cmp(&b.received_at)
    }
}
```

### Nonce-Aware Ordering

```rust
/// Tracks nonce dependencies per signer
pub struct NonceTracker {
    /// Current on-chain nonce per signer
    confirmed_nonces: HashMap<Address, U256>,
    /// Pending nonces in flight
    pending_nonces: HashMap<Address, BTreeSet<U256>>,
}

impl NonceTracker {
    /// Check if operation can be included (no nonce gap)
    pub fn is_ready(&self, op: &OpEnvelope) -> bool {
        let confirmed = self.confirmed_nonces
            .get(&op.signer)
            .copied()
            .unwrap_or(U256::ZERO);

        let pending = self.pending_nonces
            .get(&op.signer)
            .and_then(|s| s.last().copied())
            .unwrap_or(confirmed);

        // Ready if nonce is exactly next expected
        op.nonce == pending + U256::from(1)
    }

    /// Get operations for a signer in nonce order
    pub fn get_ordered_for_signer(
        &self,
        signer: Address,
        ops: &[OpEnvelope],
    ) -> Vec<&OpEnvelope> {
        let mut signer_ops: Vec<_> = ops.iter()
            .filter(|op| op.signer == signer)
            .collect();

        signer_ops.sort_by_key(|op| op.nonce);
        signer_ops
    }
}
```

## Chain Monitor

```rust
/// Monitors chain state for adaptive batching decisions
pub struct ChainMonitor {
    /// Provider for chain queries
    provider: Arc<DynProvider>,
    /// Recent base fee samples
    base_fee_history: VecDeque<BaseFeeSnapshot>,
    /// Current chain state
    state: RwLock<ChainState>,
    /// Update interval
    poll_interval: Duration,
}

#[derive(Clone)]
pub struct ChainState {
    pub block_number: u64,
    pub base_fee: u64,
    pub base_fee_ema: f64,
    pub base_fee_trend: f64,  // [-1, 1]
    pub block_gas_limit: u64,
    pub recent_utilization: f64,
    pub last_updated: Instant,
}

pub struct BaseFeeSnapshot {
    pub block_number: u64,
    pub base_fee: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub timestamp: Instant,
}

impl ChainMonitor {
    pub async fn run(self: Arc<Self>, mut shutdown: broadcast::Receiver<()>) {
        let mut interval = tokio::time::interval(self.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.update().await {
                        tracing::warn!(error = %e, "Failed to update chain state");
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    }

    async fn update(&self) -> eyre::Result<()> {
        let block = self.provider.get_block_by_number(
            BlockNumberOrTag::Latest,
            BlockTransactionsKind::Hashes,
        ).await?.ok_or_eyre("Block not found")?;

        let snapshot = BaseFeeSnapshot {
            block_number: block.header.number,
            base_fee: block.header.base_fee_per_gas.unwrap_or(0),
            gas_used: block.header.gas_used,
            gas_limit: block.header.gas_limit,
            timestamp: Instant::now(),
        };

        self.update_state(snapshot).await;
        Ok(())
    }

    pub fn current_state(&self) -> ChainState {
        self.state.read().unwrap().clone()
    }

    pub fn fee_pressure(&self) -> f64 {
        // Returns 0-1 based on proximity to max fee
        // Used by adaptive batcher
    }

    pub fn trend(&self) -> f64 {
        // Returns -1 to 1 based on fee direction
    }
}
```

## Adaptive Batch Sizing

```rust
/// Computes optimal batch size based on chain conditions and backlog
pub struct AdaptiveSizer {
    config: AdaptiveConfig,
}

pub struct AdaptiveConfig {
    /// Block gas limit
    pub block_gas_limit: u64,
    /// Estimated gas per operation
    pub gas_per_op: u64,
    /// Maximum base fee we'll pay (gwei)
    pub max_base_fee: u64,
    /// Soft cap where we start being conservative
    pub soft_cap_base_fee: u64,
    /// Target base fee for comfortable operation
    pub target_base_fee: u64,
    /// Queue depth threshold for "backed up"
    pub backlog_threshold: usize,
    /// Maximum operations per batch
    pub max_batch_ops: usize,
    /// Minimum operations per batch
    pub min_batch_ops: usize,
}

impl AdaptiveSizer {
    /// Calculate target gas budget for next batch
    pub fn target_gas(&self, chain: &ChainState, queue_depth: usize) -> u64 {
        let fee_pressure = self.fee_pressure(chain.base_fee);
        let queue_pressure = self.queue_pressure(queue_depth);
        let trend_factor = 1.0 + 0.5 * chain.base_fee_trend;

        // Net pressure: positive = reduce, negative = increase
        let adjusted_fee_pressure = (fee_pressure * trend_factor).clamp(0.0, 1.0);
        let net_pressure = adjusted_fee_pressure - queue_pressure;

        // Map to utilization target: [-1, 1] -> [0.9, 0.1]
        let utilization = (0.5 - 0.4 * net_pressure).clamp(0.1, 0.9);

        (self.config.block_gas_limit as f64 * utilization) as u64
    }

    /// Calculate batch size from gas budget
    pub fn batch_size(&self, chain: &ChainState, queue_depth: usize) -> usize {
        if chain.base_fee >= self.config.max_base_fee {
            return 0; // Don't batch at all
        }

        let gas_budget = self.target_gas(chain, queue_depth);
        let ops = (gas_budget / self.config.gas_per_op) as usize;

        ops.min(queue_depth)
           .min(self.config.max_batch_ops)
           .max(self.config.min_batch_ops)
    }

    fn fee_pressure(&self, base_fee: u64) -> f64 {
        if base_fee <= self.config.target_base_fee {
            0.0
        } else if base_fee >= self.config.max_base_fee {
            1.0
        } else {
            let range = self.config.max_base_fee - self.config.target_base_fee;
            (base_fee - self.config.target_base_fee) as f64 / range as f64
        }
    }

    fn queue_pressure(&self, queue_depth: usize) -> f64 {
        (queue_depth as f64 / self.config.backlog_threshold as f64).min(1.0)
    }
}
```

## PendingBatchFut

```rust
/// A future representing an in-flight batch
///
/// Responsibilities:
/// 1. Simulate operations and evict failures
/// 2. Build and submit transaction
/// 3. Monitor for inclusion, escalate fees if needed
/// 4. Resolve with final statuses for all operations
pub struct PendingBatchFut {
    /// Unique batch identifier
    batch_id: Uuid,
    /// Operations in this batch
    ops: Vec<OpEnvelope>,
    /// Gas budget for this batch
    gas_budget: u64,
    /// Provider for chain interaction
    provider: Arc<DynProvider>,
    /// Wallet for signing
    wallet: Arc<LocalWallet>,
    /// Registry contract
    registry: Address,
    /// Channel to send result
    result_tx: Option<oneshot::Sender<FinalizedBatch>>,
    /// Current state
    state: BatchState,
    /// Configuration
    config: PendingBatchConfig,
    /// Metrics recorder
    metrics: BatchMetrics,
}

pub struct PendingBatchConfig {
    /// Time to wait before resubmitting with higher gas
    pub resubmit_timeout: Duration,
    /// Maximum fee escalation multiplier
    pub max_fee_multiplier: f64,
    /// Fee escalation step (e.g., 1.1 = 10% increase)
    pub fee_escalation_step: f64,
    /// Maximum resubmission attempts
    pub max_resubmissions: u32,
    /// Simulation timeout
    pub simulation_timeout: Duration,
}

enum BatchState {
    /// Initial state, needs simulation
    Pending,
    /// Simulating operations
    Simulating,
    /// Ready to submit
    ReadyToSubmit {
        calldata: Bytes,
        gas_estimate: u64,
    },
    /// Transaction submitted, waiting for inclusion
    Submitted {
        tx_hash: B256,
        submitted_at: Instant,
        nonce: u64,
        gas_price: u128,
    },
    /// Resubmitting with higher gas
    Resubmitting {
        previous_hash: B256,
        attempt: u32,
    },
    /// Batch finalized
    Finalized(FinalizedBatch),
    /// Batch failed terminally
    Failed(String),
}

impl PendingBatchFut {
    pub fn new(
        ops: Vec<OpEnvelope>,
        gas_budget: u64,
        provider: Arc<DynProvider>,
        wallet: Arc<LocalWallet>,
        registry: Address,
        config: PendingBatchConfig,
    ) -> (Self, oneshot::Receiver<FinalizedBatch>) {
        let (tx, rx) = oneshot::channel();

        let fut = Self {
            batch_id: Uuid::new_v4(),
            ops,
            gas_budget,
            provider,
            wallet,
            registry,
            result_tx: Some(tx),
            state: BatchState::Pending,
            config,
            metrics: BatchMetrics::new(),
        };

        (fut, rx)
    }

    /// Run the batch to completion
    pub async fn run(mut self) -> FinalizedBatch {
        let created_at = Instant::now();

        // Phase 1: Simulate and evict failing ops
        let (valid_ops, evicted) = self.simulate_and_evict().await;
        self.ops = valid_ops;

        if self.ops.is_empty() {
            return self.finalize_empty(evicted);
        }

        // Phase 2: Build multicall transaction
        let (calldata, gas_estimate) = self.build_multicall();

        // Phase 3: Submit and monitor
        let result = self.submit_and_monitor(calldata, gas_estimate).await;

        // Phase 4: Parse results and build final statuses
        self.build_finalized_batch(result, evicted, created_at)
    }

    async fn simulate_and_evict(&self) -> (Vec<OpEnvelope>, HashMap<Uuid, OpStatus>) {
        let mut valid = Vec::with_capacity(self.ops.len());
        let mut evicted = HashMap::new();

        // Build simulation multicall with allowFailure = true
        let calls: Vec<_> = self.ops.iter().map(|op| {
            Multicall3::Call3 {
                target: op.op.target(),
                allowFailure: true,
                callData: op.op.encode_calldata(),
            }
        }).collect();

        // Simulate
        let multicall = Multicall3::new(MULTICALL3_ADDR, &self.provider);
        match multicall.aggregate3(calls).call().await {
            Ok(results) => {
                for (op, result) in self.ops.iter().zip(results.returnData.iter()) {
                    if result.success {
                        valid.push(op.clone());
                    } else {
                        let reason = parse_revert_reason(&result.returnData);
                        evicted.insert(op.id, OpStatus::Failed {
                            reason: FailureReason::SimulationReverted(reason),
                            revert_data: Some(result.returnData.clone()),
                        });
                    }
                }
            }
            Err(e) => {
                // Full simulation failed, try individual ops
                for op in &self.ops {
                    if self.simulate_single(op).await.is_ok() {
                        valid.push(op.clone());
                    } else {
                        evicted.insert(op.id, OpStatus::Failed {
                            reason: FailureReason::SimulationReverted(e.to_string()),
                            revert_data: None,
                        });
                    }
                }
            }
        }

        (valid, evicted)
    }

    fn build_multicall(&self) -> (Bytes, u64) {
        let calls: Vec<_> = self.ops.iter().map(|op| {
            Multicall3::Call3 {
                target: op.op.target(),
                allowFailure: true, // Still allow failure for individual ops
                callData: op.op.encode_calldata(),
            }
        }).collect();

        let calldata = Multicall3::aggregate3Call { calls }.abi_encode().into();
        let gas_estimate = self.ops.iter()
            .map(|op| op.op.estimated_gas())
            .sum::<u64>() + 50_000; // Multicall overhead

        (calldata, gas_estimate)
    }

    async fn submit_and_monitor(
        &mut self,
        calldata: Bytes,
        gas_estimate: u64,
    ) -> Result<TransactionReceipt, BatchError> {
        let mut attempts = 0;
        let mut current_gas_price = self.get_current_gas_price().await?;

        loop {
            // Build transaction
            let tx = TransactionRequest::default()
                .to(MULTICALL3_ADDR)
                .input(calldata.clone().into())
                .gas(gas_estimate as u128)
                .max_fee_per_gas(current_gas_price)
                .max_priority_fee_per_gas(current_gas_price / 10);

            // Sign and send
            let pending = self.provider.send_transaction(tx).await?;
            let tx_hash = *pending.tx_hash();

            self.metrics.record_submission(tx_hash, current_gas_price);

            // Wait for inclusion with timeout
            match tokio::time::timeout(
                self.config.resubmit_timeout,
                pending.get_receipt(),
            ).await {
                Ok(Ok(receipt)) => return Ok(receipt),
                Ok(Err(e)) => {
                    // Transaction failed
                    return Err(BatchError::TransactionFailed(e.to_string()));
                }
                Err(_) => {
                    // Timeout - escalate fees
                    attempts += 1;
                    if attempts >= self.config.max_resubmissions {
                        return Err(BatchError::MaxResubmissionsExceeded);
                    }

                    current_gas_price = (current_gas_price as f64
                        * self.config.fee_escalation_step) as u128;

                    let max_gas = (self.get_current_gas_price().await? as f64
                        * self.config.max_fee_multiplier) as u128;

                    if current_gas_price > max_gas {
                        return Err(BatchError::GasPriceTooHigh);
                    }

                    tracing::info!(
                        batch_id = %self.batch_id,
                        attempt = attempts,
                        new_gas_price = current_gas_price,
                        "Resubmitting batch with higher gas"
                    );
                }
            }
        }
    }

    fn build_finalized_batch(
        &self,
        result: Result<TransactionReceipt, BatchError>,
        mut evicted: HashMap<Uuid, OpStatus>,
        created_at: Instant,
    ) -> FinalizedBatch {
        let mut statuses = evicted;

        match result {
            Ok(receipt) => {
                // Parse multicall results from receipt
                let call_results = self.parse_multicall_results(&receipt);

                for (op, result) in self.ops.iter().zip(call_results.iter()) {
                    let status = if result.success {
                        OpStatus::Finalized {
                            tx_hash: receipt.transaction_hash,
                            block_number: receipt.block_number.unwrap_or(0),
                            gas_used: receipt.gas_used,
                        }
                    } else {
                        OpStatus::Failed {
                            reason: FailureReason::ExecutionReverted(
                                parse_revert_reason(&result.returnData)
                            ),
                            revert_data: Some(result.returnData.clone()),
                        }
                    };
                    statuses.insert(op.id, status);
                }

                FinalizedBatch {
                    batch_id: self.batch_id,
                    tx_hash: Some(receipt.transaction_hash),
                    block_number: receipt.block_number,
                    gas_used: receipt.gas_used,
                    statuses,
                    timing: BatchTiming {
                        created_at,
                        simulation_completed_at: self.metrics.simulation_completed_at,
                        submitted_at: self.metrics.submitted_at,
                        finalized_at: Instant::now(),
                        total_duration: created_at.elapsed(),
                        resubmission_count: self.metrics.resubmission_count,
                    },
                }
            }
            Err(e) => {
                // All ops failed
                for op in &self.ops {
                    statuses.insert(op.id, OpStatus::Failed {
                        reason: FailureReason::Unknown(e.to_string()),
                        revert_data: None,
                    });
                }

                FinalizedBatch {
                    batch_id: self.batch_id,
                    tx_hash: None,
                    block_number: None,
                    gas_used: 0,
                    statuses,
                    timing: BatchTiming {
                        created_at,
                        simulation_completed_at: self.metrics.simulation_completed_at,
                        submitted_at: self.metrics.submitted_at,
                        finalized_at: Instant::now(),
                        total_duration: created_at.elapsed(),
                        resubmission_count: self.metrics.resubmission_count,
                    },
                }
            }
        }
    }
}
```

## OpsBatcher

```rust
/// Main batcher coordinating all operations
pub struct OpsBatcher {
    /// Configuration
    config: OpsBatcherConfig,
    /// Provider for chain interaction
    provider: Arc<DynProvider>,
    /// Signing wallet
    wallet: Arc<LocalWallet>,
    /// Registry contract address
    registry: Address,
    /// Request tracker for status updates
    tracker: Arc<RequestTracker>,
    /// Chain state monitor
    chain_monitor: Arc<ChainMonitor>,
    /// Adaptive batch sizer
    sizer: AdaptiveSizer,
    /// Nonce tracker for dependency ordering
    nonce_tracker: NonceTracker,
    /// Ordering policy
    ordering_policy: Arc<dyn OrderingPolicy>,
    /// Pending operations queue
    pending_ops: VecDeque<OpEnvelope>,
    /// In-flight batches
    in_flight: JoinSet<FinalizedBatch>,
    /// Semaphore for limiting concurrent batches
    batch_permits: Arc<Semaphore>,
    /// Receiver for new operations
    op_rx: mpsc::Receiver<OpEnvelope>,
    /// Metrics
    metrics: Arc<OpsBatcherMetrics>,
}

pub struct OpsBatcherConfig {
    /// Batch window duration
    pub batch_window: Duration,
    /// Maximum concurrent batches
    pub max_concurrent_batches: usize,
    /// Adaptive sizing config
    pub adaptive: AdaptiveConfig,
    /// Pending batch config
    pub pending_batch: PendingBatchConfig,
}

impl OpsBatcher {
    pub async fn run(mut self, mut shutdown: broadcast::Receiver<()>) {
        let mut batch_interval = tokio::time::interval(self.config.batch_window);

        loop {
            tokio::select! {
                // Receive new operations
                Some(op) = self.op_rx.recv() => {
                    self.handle_new_op(op).await;
                }

                // Batch timer fired
                _ = batch_interval.tick() => {
                    self.maybe_spawn_batch().await;
                }

                // A batch completed
                Some(result) = self.in_flight.join_next() => {
                    match result {
                        Ok(finalized) => self.handle_finalized_batch(finalized).await,
                        Err(e) => tracing::error!(error = %e, "Batch task panicked"),
                    }
                }

                // Shutdown signal
                _ = shutdown.recv() => {
                    tracing::info!("OpsBatcher shutting down");
                    break;
                }
            }
        }

        // Drain in-flight batches on shutdown
        while let Some(result) = self.in_flight.join_next().await {
            if let Ok(finalized) = result {
                self.handle_finalized_batch(finalized).await;
            }
        }
    }

    async fn handle_new_op(&mut self, op: OpEnvelope) {
        // Pre-flight checks
        if let Err(e) = self.pre_flight_checks(&op).await {
            // Immediately fail the operation
            self.tracker.set_status(
                op.id,
                GatewayRequestState::Failed {
                    reason: e.to_string(),
                    code: GatewayErrorCode::BadRequest,
                },
            ).await;
            return;
        }

        // Update tracker status
        self.tracker.set_status(op.id, GatewayRequestState::Queued).await;

        // Add to pending queue
        self.pending_ops.push_back(op);

        self.metrics.queue_depth.set(self.pending_ops.len() as i64);
    }

    async fn pre_flight_checks(&self, op: &OpEnvelope) -> eyre::Result<()> {
        // 1. Validate signature format
        op.op.validate_signature()?;

        // 2. Check nonce is reasonable
        let on_chain_nonce = self.get_on_chain_nonce(op.signer).await?;
        if op.nonce < on_chain_nonce {
            eyre::bail!("Nonce too low: {} < {}", op.nonce, on_chain_nonce);
        }
        if op.nonce > on_chain_nonce + U256::from(100) {
            eyre::bail!("Nonce too high: {} > {} + 100", op.nonce, on_chain_nonce);
        }

        // 3. Operation-specific validation
        op.op.validate()?;

        Ok(())
    }

    async fn maybe_spawn_batch(&mut self) {
        if self.pending_ops.is_empty() {
            return;
        }

        // Check if we have permits available
        let permit = match self.batch_permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("No batch permits available");
                return;
            }
        };

        // Get current chain state
        let chain_state = self.chain_monitor.current_state();

        // Check if base fee is acceptable
        if chain_state.base_fee >= self.config.adaptive.max_base_fee {
            tracing::warn!(
                base_fee = chain_state.base_fee,
                max = self.config.adaptive.max_base_fee,
                "Base fee too high, skipping batch"
            );
            return;
        }

        // Calculate batch size
        let batch_size = self.sizer.batch_size(&chain_state, self.pending_ops.len());
        if batch_size == 0 {
            return;
        }

        // Select and order operations
        let ops = self.select_ops_for_batch(batch_size);
        if ops.is_empty() {
            return;
        }

        // Calculate gas budget
        let gas_budget = self.sizer.target_gas(&chain_state, self.pending_ops.len());

        // Update statuses to Batching
        for op in &ops {
            self.tracker.set_status(op.id, GatewayRequestState::Batching).await;
        }

        // Create and spawn PendingBatchFut
        let (batch_fut, _rx) = PendingBatchFut::new(
            ops,
            gas_budget,
            self.provider.clone(),
            self.wallet.clone(),
            self.registry,
            self.config.pending_batch.clone(),
        );

        let batch_id = batch_fut.batch_id;
        tracing::info!(batch_id = %batch_id, ops = batch_fut.ops.len(), "Spawning batch");

        self.in_flight.spawn(async move {
            let result = batch_fut.run().await;
            drop(permit); // Release permit when done
            result
        });

        self.metrics.batches_spawned.inc();
    }

    fn select_ops_for_batch(&mut self, target_size: usize) -> Vec<OpEnvelope> {
        // Sort pending ops by policy
        let mut candidates: Vec<_> = self.pending_ops.drain(..).collect();
        candidates.sort_by(|a, b| self.ordering_policy.compare(a, b));

        let mut selected = Vec::with_capacity(target_size);
        let mut deferred = Vec::new();

        for op in candidates {
            if selected.len() >= target_size {
                deferred.push(op);
                continue;
            }

            // Check nonce dependencies
            if self.nonce_tracker.is_ready(&op) {
                self.nonce_tracker.mark_pending(&op);
                selected.push(op);
            } else {
                // Defer operations with nonce gaps
                deferred.push(op);
            }
        }

        // Put deferred ops back in queue
        for op in deferred {
            self.pending_ops.push_back(op);
        }

        selected
    }

    async fn handle_finalized_batch(&mut self, batch: FinalizedBatch) {
        tracing::info!(
            batch_id = %batch.batch_id,
            tx_hash = ?batch.tx_hash,
            duration_ms = batch.timing.total_duration.as_millis(),
            "Batch finalized"
        );

        // Update all operation statuses in tracker
        for (id, status) in &batch.statuses {
            let state = match status {
                OpStatus::Finalized { tx_hash, .. } => {
                    GatewayRequestState::Finalized {
                        tx_hash: *tx_hash,
                    }
                }
                OpStatus::Failed { reason, .. } => {
                    GatewayRequestState::Failed {
                        reason: format!("{:?}", reason),
                        code: GatewayErrorCode::TransactionReverted,
                    }
                }
                OpStatus::Evicted { reason } => {
                    // Re-queue evicted operations
                    // (handled separately)
                    continue;
                }
            };

            self.tracker.set_status(*id, state).await;
        }

        // Update nonce tracker with confirmed nonces
        if let Some(block) = batch.block_number {
            self.nonce_tracker.confirm_batch(&batch);
        }

        // Record metrics
        self.metrics.batches_finalized.inc();
        self.metrics.ops_finalized.inc_by(
            batch.statuses.values()
                .filter(|s| matches!(s, OpStatus::Finalized { .. }))
                .count() as u64
        );
        self.metrics.batch_duration.observe(
            batch.timing.total_duration.as_secs_f64()
        );
    }
}
```

## Metrics

```rust
/// Prometheus metrics for the batcher
pub struct OpsBatcherMetrics {
    // Queue metrics
    pub queue_depth: IntGauge,
    pub queue_oldest_age_seconds: Gauge,

    // Batch metrics
    pub batches_spawned: IntCounter,
    pub batches_finalized: IntCounter,
    pub batches_failed: IntCounter,
    pub batch_size: Histogram,
    pub batch_duration: Histogram,

    // Operation metrics
    pub ops_received: IntCounterVec,   // by type
    pub ops_finalized: IntCounter,
    pub ops_failed: IntCounterVec,     // by reason
    pub ops_evicted: IntCounterVec,    // by reason

    // Chain metrics
    pub base_fee_gwei: Gauge,
    pub base_fee_trend: Gauge,
    pub gas_price_gwei: Gauge,

    // Transaction metrics
    pub tx_resubmissions: IntCounter,
    pub tx_gas_used: Histogram,

    // Signer metrics
    pub signer_balance_eth: Gauge,
    pub signer_nonce: IntGauge,

    // Timing metrics
    pub simulation_duration: Histogram,
    pub submission_duration: Histogram,
    pub confirmation_duration: Histogram,
}

impl OpsBatcherMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            queue_depth: IntGauge::new(
                "ops_batcher_queue_depth",
                "Number of operations waiting to be batched"
            ).unwrap(),

            base_fee_gwei: Gauge::new(
                "ops_batcher_base_fee_gwei",
                "Current base fee in gwei"
            ).unwrap(),

            batch_duration: Histogram::with_opts(
                HistogramOpts::new(
                    "ops_batcher_batch_duration_seconds",
                    "Time from batch creation to finalization"
                ).buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0])
            ).unwrap(),

            // ... etc
        }
    }
}
```

## Handle Type

```rust
/// Handle for submitting operations to the batcher
#[derive(Clone)]
pub struct OpsBatcherHandle {
    tx: mpsc::Sender<OpEnvelope>,
}

impl OpsBatcherHandle {
    pub async fn submit(&self, op: OpEnvelope) -> Result<(), SendError<OpEnvelope>> {
        self.tx.send(op).await
    }

    pub fn try_submit(&self, op: OpEnvelope) -> Result<(), TrySendError<OpEnvelope>> {
        self.tx.try_send(op)
    }
}
```

## Integration

```rust
// In routes.rs or lib.rs

pub async fn start_ops_batcher(
    provider: Arc<DynProvider>,
    wallet: LocalWallet,
    registry: Address,
    tracker: Arc<RequestTracker>,
    config: OpsBatcherConfig,
    shutdown: broadcast::Receiver<()>,
) -> OpsBatcherHandle {
    let (tx, rx) = mpsc::channel(4096);

    // Start chain monitor
    let chain_monitor = Arc::new(ChainMonitor::new(
        provider.clone(),
        Duration::from_secs(1),
    ));

    tokio::spawn(chain_monitor.clone().run(shutdown.resubscribe()));

    // Create batcher
    let batcher = OpsBatcher {
        config,
        provider,
        wallet: Arc::new(wallet),
        registry,
        tracker,
        chain_monitor,
        sizer: AdaptiveSizer::new(config.adaptive),
        nonce_tracker: NonceTracker::new(),
        ordering_policy: Arc::new(GreedyCreateFirstPolicy),
        pending_ops: VecDeque::new(),
        in_flight: JoinSet::new(),
        batch_permits: Arc::new(Semaphore::new(config.max_concurrent_batches)),
        op_rx: rx,
        metrics: Arc::new(OpsBatcherMetrics::new()),
    };

    tokio::spawn(batcher.run(shutdown));

    OpsBatcherHandle { tx }
}
```

## Summary

| Component | Responsibility |
|-----------|----------------|
| `OpsBatcher` | Orchestrates batching, ordering, permits, status updates |
| `PendingBatchFut` | Owns batch lifecycle: simulate → submit → monitor → finalize |
| `ChainMonitor` | Tracks base fee, trend, capacity in background |
| `AdaptiveSizer` | Computes batch size from chain state + backlog |
| `NonceTracker` | Ensures nonce ordering, detects gaps |
| `OrderingPolicy` | Defines operation precedence (pluggable) |
| `OpsBatcherHandle` | Public API for submitting operations |
| `RequestTracker` | Persistent operation status storage |
