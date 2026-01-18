//! Metrics for the OpsBatcher system
//!
//! This module provides a metrics interface that can be backed by Prometheus
//! or used as a no-op for testing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Metrics for the OpsBatcher system
#[derive(Clone, Default)]
pub struct OpsBatcherMetrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    queue_depth: AtomicU64,
    batches_spawned: AtomicU64,
    batches_finalized: AtomicU64,
    batches_failed: AtomicU64,
    ops_finalized: AtomicU64,
    tx_submissions: AtomicU64,
    tx_resubmissions: AtomicU64,
    simulation_evictions: AtomicU64,
    queue_oldest_age: AtomicU64,
    queue_pressure: AtomicU64,
}

impl OpsBatcherMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    // Queue metrics
    pub fn set_queue_depth(&self, depth: usize) {
        self.inner
            .queue_depth
            .store(depth as u64, Ordering::Relaxed);
    }

    pub fn get_queue_depth(&self) -> u64 {
        self.inner.queue_depth.load(Ordering::Relaxed)
    }

    pub fn set_queue_oldest_age(&self, _age_seconds: f64) {
        // No-op for now
    }

    // Batch metrics
    pub fn inc_batches_spawned(&self) {
        self.inner.batches_spawned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_batches_finalized(&self) {
        self.inner.batches_finalized.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_batches_failed(&self) {
        self.inner.batches_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_batch_size(&self, _size: usize) {
        // No-op for now
    }

    pub fn observe_batch_duration(&self, _duration_secs: f64) {
        // No-op for now
    }

    // Operation metrics
    pub fn inc_ops_received(&self, _op_type: &str) {
        // No-op for now
    }

    pub fn inc_ops_finalized(&self, count: u64) {
        self.inner.ops_finalized.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_ops_failed(&self, _reason: &str) {
        // No-op for now
    }

    pub fn inc_ops_evicted(&self, _reason: &str) {
        // No-op for now
    }

    // Chain metrics
    pub fn set_base_fee_gwei(&self, _fee: f64) {
        // No-op for now
    }

    pub fn set_base_fee_trend(&self, _trend: f64) {
        // No-op for now
    }

    pub fn set_block_utilization(&self, _utilization: f64) {
        // No-op for now
    }

    // Transaction metrics
    pub fn inc_tx_submissions(&self) {
        self.inner.tx_submissions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_resubmissions(&self) {
        self.inner.tx_resubmissions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_tx_gas_used(&self, _gas: u64) {
        // No-op for now
    }

    pub fn observe_tx_confirmation_time(&self, _seconds: f64) {
        // No-op for now
    }

    // Signer metrics
    pub fn set_signer_balance(&self, _balance_eth: f64) {
        // No-op for now
    }

    pub fn set_signer_nonce(&self, _nonce: u64) {
        // No-op for now
    }

    // Adaptive sizing metrics
    pub fn set_target_utilization(&self, _utilization: f64) {
        // No-op for now
    }

    pub fn set_fee_pressure(&self, _pressure: f64) {
        // No-op for now
    }

    pub fn set_queue_pressure(&self, _pressure: f64) {
        // No-op for now
    }

    pub fn set_net_pressure(&self, _pressure: f64) {
        // No-op for now
    }

    // Simulation metrics
    pub fn observe_simulation_duration(&self, _seconds: f64) {
        // No-op for now
    }

    pub fn inc_simulation_evictions(&self, count: u64) {
        self.inner
            .simulation_evictions
            .fetch_add(count, Ordering::Relaxed);
    }
}

/// Recorder for per-batch metrics
#[derive(Clone)]
pub struct BatchMetricsRecorder {
    metrics: OpsBatcherMetrics,
    batch_size: usize,
    start_time: std::time::Instant,
}

impl BatchMetricsRecorder {
    pub fn new(metrics: OpsBatcherMetrics, batch_size: usize) -> Self {
        Self {
            metrics,
            batch_size,
            start_time: std::time::Instant::now(),
        }
    }

    pub fn record_submission(&self) {
        self.metrics.inc_tx_submissions();
    }

    pub fn record_resubmission(&self) {
        self.metrics.inc_tx_resubmissions();
    }

    pub fn record_simulation_duration(&self, seconds: f64) {
        self.metrics.observe_simulation_duration(seconds);
    }

    pub fn record_evictions(&self, count: usize) {
        self.metrics.inc_simulation_evictions(count as u64);
    }

    pub fn record_finalized(&self, success_count: usize, gas_used: u64) {
        self.metrics.inc_batches_finalized();
        self.metrics.observe_batch_size(self.batch_size);
        self.metrics
            .observe_batch_duration(self.start_time.elapsed().as_secs_f64());
        self.metrics.inc_ops_finalized(success_count as u64);
        self.metrics.observe_tx_gas_used(gas_used);
    }

    pub fn record_failed(&self) {
        self.metrics.inc_batches_failed();
        self.metrics
            .observe_batch_duration(self.start_time.elapsed().as_secs_f64());
    }
}
