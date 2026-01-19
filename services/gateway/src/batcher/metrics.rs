//! Metrics for the OpsBatcher system
//!
//! This module provides a metrics interface that can be backed by Prometheus
//! or used as a no-op for testing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Metrics for the OpsBatcher system
#[derive(Clone, Default)]
pub struct OpsBatcherMetrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    // Queue metrics
    queue_depth: AtomicU64,

    // Operation metrics
    ops_received: RwLock<HashMap<&'static str, u64>>,
    ops_finalized: AtomicU64,
    ops_failed: AtomicU64,

    // Batch metrics
    batches_spawned: AtomicU64,
    batches_completed: AtomicU64,
    batches_failed: AtomicU64,
    batch_duration_sum_ms: AtomicU64,
    batch_duration_count: AtomicU64,
    batch_size_sum: AtomicU64,
    batch_size_count: AtomicU64,

    // Transaction metrics
    tx_submissions: AtomicU64,
    simulation_evictions: AtomicU64,
}

impl OpsBatcherMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Queue metrics
    // ========================================================================

    pub fn set_queue_depth(&self, depth: usize) {
        self.inner
            .queue_depth
            .store(depth as u64, Ordering::Relaxed);
    }

    // ========================================================================
    // Operation metrics
    // ========================================================================

    pub fn inc_ops_received(&self, op_type: &'static str) {
        if let Ok(mut map) = self.inner.ops_received.write() {
            *map.entry(op_type).or_insert(0) += 1;
        }
    }

    pub fn inc_ops_finalized(&self) {
        self.inner.ops_finalized.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ops_failed(&self) {
        self.inner.ops_failed.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Batch metrics
    // ========================================================================

    pub fn inc_batches_spawned(&self) {
        self.inner.batches_spawned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_batches_completed(&self) {
        self.inner.batches_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_batches_failed(&self) {
        self.inner.batches_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_batches_finalized(&self) {
        // Alias for backwards compat
        self.inc_batches_completed();
    }

    pub fn observe_batch_duration(&self, duration_ms: u64) {
        self.inner
            .batch_duration_sum_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
        self.inner
            .batch_duration_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_batch_size(&self, size: usize) {
        self.inner
            .batch_size_sum
            .fetch_add(size as u64, Ordering::Relaxed);
        self.inner
            .batch_size_count
            .fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Transaction metrics
    // ========================================================================

    pub fn inc_tx_submissions(&self) {
        self.inner.tx_submissions.fetch_add(1, Ordering::Relaxed);
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

    pub fn record_evictions(&self, count: usize) {
        self.metrics.inc_simulation_evictions(count as u64);
    }
}
