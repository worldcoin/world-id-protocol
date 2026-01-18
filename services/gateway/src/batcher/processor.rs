//! Operation processor that integrates the pool with transaction submission.
//!
//! This processor handles the full lifecycle of operations:
//! 1. Receives ops from the ingress controller
//! 2. Submits them to the pool (with lifecycle hooks)
//! 3. Periodically takes batches from the pool
//! 4. Uses PendingBatchFuture for simulation and submission
//! 5. Updates lifecycle state on completion

use crate::batcher::pending_batch::{BatchDriver, BatchYield, PendingBatch, PendingBatchConfig};
use crate::batcher::pool::{LifecycleStage, OpPool, OpPoolConfig, StatusBatcherHooks};
use crate::batcher::order::SignupFifoOrdering;
use crate::batcher::status_batcher::StatusBatcher;
use crate::batcher::types::{OpEnvelopeInner, OpStatus};
use alloy::providers::DynProvider;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

/// Configuration for the ops processor
#[derive(Debug, Clone)]
pub struct OpsProcessorConfig {
    /// Batch window duration
    pub batch_window: Duration,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Pool configuration
    pub pool: OpPoolConfig,
    /// Maximum gas per batch
    pub max_gas: u64,
}

impl Default for OpsProcessorConfig {
    fn default() -> Self {
        Self {
            batch_window: Duration::from_millis(1000),
            max_batch_size: 50,
            pool: OpPoolConfig::default(),
            max_gas: 15_000_000,
        }
    }
}

/// Processor that handles the full operation lifecycle using PendingBatchFuture.
///
/// This processor:
/// - Receives operations from an ingress channel
/// - Collects operations into batches based on time and size limits
/// - Uses `PendingBatchFuture` for transaction simulation and submission
/// - Handles individual operation failures (via allowFailure=true in multicall)
/// - Updates operation lifecycle state through the pool
pub struct OpsProcessor {
    /// Receiver for incoming operations
    rx: mpsc::Receiver<OpEnvelopeInner>,
    /// Registry for contract calls
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    /// Operation pool with lifecycle hooks
    pool: Arc<OpPool<SignupFifoOrdering<OpEnvelopeInner>, StatusBatcherHooks>>,
    /// Status batcher for updates
    status_batcher: StatusBatcher,
    /// Configuration
    config: OpsProcessorConfig,
}

impl OpsProcessor {
    pub fn new(
        rx: mpsc::Receiver<OpEnvelopeInner>,
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        status_batcher: StatusBatcher,
        config: OpsProcessorConfig,
    ) -> Self {
        let hooks = StatusBatcherHooks::new(status_batcher.clone());
        let pool = Arc::new(OpPool::with_hooks(config.pool.clone(), hooks));

        Self {
            rx,
            registry,
            pool,
            status_batcher,
            config,
        }
    }

    /// Run the processor loop
    pub async fn run(mut self) {
        // Get the provider directly from the registry (already type-erased DynProvider)
        let provider: Arc<DynProvider> = self.registry.provider().clone();

        tracing::info!(
            batch_window_ms = self.config.batch_window.as_millis(),
            max_batch_size = self.config.max_batch_size,
            max_gas = self.config.max_gas,
            "ops_processor.started"
        );

        loop {
            // Wait for first operation
            let Some(first) = self.rx.recv().await else {
                tracing::info!("ops_processor.channel_closed");
                break;
            };

            // Submit first op to pool
            let first_id = first.id;
            if let Err(e) = self.pool.submit(first).await {
                tracing::warn!(op_id = %first_id, error = %e, "ops_processor.submit_failed");
                continue;
            }

            // Collect more ops within the batch window
            let deadline = tokio::time::Instant::now() + self.config.batch_window;
            loop {
                let ready_count = self.pool.ready_count().await;
                if ready_count >= self.config.max_batch_size {
                    break;
                }

                match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                    Ok(Some(op)) => {
                        let op_id = op.id;
                        if let Err(e) = self.pool.submit(op).await {
                            tracing::warn!(op_id = %op_id, error = %e, "ops_processor.submit_failed");
                        }
                    }
                    Ok(None) => {
                        tracing::info!("ops_processor.channel_closed_while_batching");
                        break;
                    }
                    Err(_) => break, // Timeout
                }
            }

            // Take batch from pool
            let ops = self.pool.take_batch(self.config.max_batch_size).await;
            if ops.is_empty() {
                continue;
            }

            let batch_id = Uuid::new_v4();
            let op_ids: Vec<Uuid> = ops.iter().map(|op| op.id).collect();

            // Mark ops as batched
            self.pool.mark_batched(&op_ids, batch_id).await;

            tracing::info!(
                batch_id = %batch_id,
                size = ops.len(),
                "ops_processor.batch_started"
            );

            // Create PendingBatchConfig with registry
            let batch_config = PendingBatchConfig::new(self.registry.clone())
                .with_max_gas(self.config.max_gas);

            // Initialize PendingBatchFuture
            let (batch_future, op_sender) = PendingBatch::init(
                provider.clone(),
                batch_config,
                None, // No metrics recorder for now
            );

            // Send all ops to the batch
            for op in ops {
                if op_sender.send(op).await.is_err() {
                    tracing::warn!(batch_id = %batch_id, "ops_processor.batch_channel_closed");
                    break;
                }
            }
            // Drop sender to signal end of ops
            drop(op_sender);

            // Drive the batch through all phases using BatchDriver
            let mut driver = BatchDriver::new(batch_future);
            let mut tx_hash_str = String::new();

            while let Some(yield_item) = driver.next().await {
                match yield_item {
                    BatchYield::PhaseComplete { completed, next } => {
                        tracing::debug!(
                            batch_id = %batch_id,
                            completed = completed,
                            next = next,
                            "ops_processor.phase_complete"
                        );
                    }
                    BatchYield::Done(result) => {
                        // Handle the finalized batch result
                        if let Some(tx_hash) = result.tx_hash {
                            tx_hash_str = format!("0x{:x}", tx_hash);

                            // Mark as submitted first
                            self.pool.mark_submitted(&op_ids, &tx_hash_str).await;

                            // Check individual op statuses from the result
                            let success_count = result
                                .statuses
                                .values()
                                .filter(|s| matches!(s, OpStatus::Finalized { .. }))
                                .count();
                            let fail_count = result
                                .statuses
                                .values()
                                .filter(|s| matches!(s, OpStatus::Failed { .. }))
                                .count();

                            if fail_count == 0 {
                                // All ops succeeded
                                self.pool.mark_included(&op_ids, &tx_hash_str).await;
                                tracing::info!(
                                    batch_id = %batch_id,
                                    tx_hash = %tx_hash_str,
                                    success_count = success_count,
                                    "ops_processor.batch_finalized"
                                );
                            } else {
                                // Some ops failed - update individual statuses
                                for (op_id, status) in &result.statuses {
                                    match status {
                                        OpStatus::Finalized { .. } => {
                                            self.pool.mark_included(&[*op_id], &tx_hash_str).await;
                                        }
                                        OpStatus::Failed { reason } => {
                                            self.pool
                                                .mark_failed(
                                                    *op_id,
                                                    LifecycleStage::Submitted,
                                                    format!("{:?}", reason),
                                                )
                                                .await;
                                        }
                                        OpStatus::Evicted { reason } => {
                                            self.pool
                                                .mark_failed(
                                                    *op_id,
                                                    LifecycleStage::Batched,
                                                    format!("evicted: {:?}", reason),
                                                )
                                                .await;
                                        }
                                    }
                                }
                                tracing::info!(
                                    batch_id = %batch_id,
                                    tx_hash = %tx_hash_str,
                                    success_count = success_count,
                                    fail_count = fail_count,
                                    "ops_processor.batch_partial_success"
                                );
                            }
                        } else {
                            // No tx hash means the batch failed entirely
                            for op_id in &op_ids {
                                self.pool
                                    .mark_failed(
                                        *op_id,
                                        LifecycleStage::Batched,
                                        "batch submission failed".to_string(),
                                    )
                                    .await;
                            }
                            tracing::error!(
                                batch_id = %batch_id,
                                "ops_processor.batch_failed"
                            );
                        }
                    }
                }
            }

            // Flush status updates
            self.status_batcher.maybe_flush();
        }

        // Final flush
        self.status_batcher.flush();
        tracing::info!("ops_processor.stopped");
    }
}
