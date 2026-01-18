//! Custom SpanProcessor that records metrics on span start/end.
//!
//! This processor integrates with OpenTelemetry's span lifecycle to automatically
//! derive metrics from spans without manual instrumentation. It specifically tracks
//! metrics for batcher components.

use opentelemetry_sdk::export::trace::SpanData;
use opentelemetry_sdk::trace::SpanProcessor;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ============================================================================
// Batcher-Specific Metrics
// ============================================================================

/// Specific metrics for batcher components.
///
/// These are cached metrics derived from spans with specific names/attributes.
#[derive(Debug, Default, Clone)]
pub struct BatcherMetrics {
    // Batch lifecycle
    pub batches_started: u64,
    pub batches_completed: u64,
    pub batches_failed: u64,
    pub batch_total_duration_ns: u64,
    pub batch_avg_duration_ns: Option<u64>,

    // Validation
    pub validations_started: u64,
    pub validations_completed: u64,
    pub validation_total_duration_ns: u64,

    // Status updates
    pub status_flushes: u64,
    pub status_flush_total_duration_ns: u64,

    // Operations
    pub ops_received: u64,
    pub ops_processed: u64,
}

// ============================================================================
// Span Metrics
// ============================================================================

/// Aggregated metrics derived from spans.
///
/// This struct is cloneable and thread-safe. Clone to share between components.
#[derive(Clone)]
pub struct SpanMetrics {
    inner: Arc<SpanMetricsInner>,
}

struct SpanMetricsInner {
    /// Per-span-name counters and durations
    span_stats: Mutex<HashMap<String, SpanStats>>,
    /// Global counters
    total_spans_started: AtomicU64,
    total_spans_ended: AtomicU64,
    total_spans_errored: AtomicU64,

    // Batcher-specific atomic counters (for fast access without locks)
    batches_started: AtomicU64,
    batches_completed: AtomicU64,
    batches_failed: AtomicU64,
    batch_total_duration_ns: AtomicU64,

    validations_started: AtomicU64,
    validations_completed: AtomicU64,
    validation_total_duration_ns: AtomicU64,

    status_flushes: AtomicU64,
    status_flush_total_duration_ns: AtomicU64,

    ops_received: AtomicU64,
    ops_processed: AtomicU64,
}

/// Statistics for a specific span name.
#[derive(Debug, Clone, Default)]
pub struct SpanStats {
    /// Number of times this span started
    pub started: u64,
    /// Number of times this span ended
    pub ended: u64,
    /// Number of times this span ended with error status
    pub errored: u64,
    /// Total duration of all ended spans (nanoseconds)
    pub total_duration_ns: u64,
    /// Minimum duration observed (nanoseconds)
    pub min_duration_ns: Option<u64>,
    /// Maximum duration observed (nanoseconds)
    pub max_duration_ns: Option<u64>,
}

impl SpanStats {
    fn record_start(&mut self) {
        self.started += 1;
    }

    fn record_end(&mut self, duration_ns: u64, errored: bool) {
        self.ended += 1;
        if errored {
            self.errored += 1;
        }
        self.total_duration_ns = self.total_duration_ns.saturating_add(duration_ns);
        self.min_duration_ns = Some(
            self.min_duration_ns
                .map_or(duration_ns, |m| m.min(duration_ns)),
        );
        self.max_duration_ns = Some(
            self.max_duration_ns
                .map_or(duration_ns, |m| m.max(duration_ns)),
        );
    }

    /// Calculate average duration in nanoseconds.
    pub fn avg_duration_ns(&self) -> Option<u64> {
        if self.ended > 0 {
            Some(self.total_duration_ns / self.ended)
        } else {
            None
        }
    }
}

impl SpanMetrics {
    /// Create a new SpanMetrics instance.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SpanMetricsInner {
                span_stats: Mutex::new(HashMap::new()),
                total_spans_started: AtomicU64::new(0),
                total_spans_ended: AtomicU64::new(0),
                total_spans_errored: AtomicU64::new(0),
                batches_started: AtomicU64::new(0),
                batches_completed: AtomicU64::new(0),
                batches_failed: AtomicU64::new(0),
                batch_total_duration_ns: AtomicU64::new(0),
                validations_started: AtomicU64::new(0),
                validations_completed: AtomicU64::new(0),
                validation_total_duration_ns: AtomicU64::new(0),
                status_flushes: AtomicU64::new(0),
                status_flush_total_duration_ns: AtomicU64::new(0),
                ops_received: AtomicU64::new(0),
                ops_processed: AtomicU64::new(0),
            }),
        }
    }

    /// Record a span start event.
    fn on_start(&self, span_name: &str) {
        self.inner
            .total_spans_started
            .fetch_add(1, Ordering::Relaxed);

        // Track batcher-specific span starts
        match span_name {
            "batch" => {
                self.inner.batches_started.fetch_add(1, Ordering::Relaxed);
            }
            "validation_worker" | "simulate_batch" | "validate" => {
                self.inner
                    .validations_started
                    .fetch_add(1, Ordering::Relaxed);
            }
            "op.received" => {
                self.inner.ops_received.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        let mut stats = self
            .inner
            .span_stats
            .lock()
            .expect("SpanMetrics lock poisoned");
        stats
            .entry(span_name.to_string())
            .or_default()
            .record_start();
    }

    /// Record a span end event.
    fn on_end(&self, span_name: &str, duration_ns: u64, errored: bool) {
        self.inner.total_spans_ended.fetch_add(1, Ordering::Relaxed);
        if errored {
            self.inner
                .total_spans_errored
                .fetch_add(1, Ordering::Relaxed);
        }

        // Track batcher-specific span ends
        match span_name {
            "batch" => {
                if errored {
                    self.inner.batches_failed.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.inner.batches_completed.fetch_add(1, Ordering::Relaxed);
                }
                self.inner
                    .batch_total_duration_ns
                    .fetch_add(duration_ns, Ordering::Relaxed);
            }
            "validation_worker" | "simulate_batch" | "validate" => {
                self.inner
                    .validations_completed
                    .fetch_add(1, Ordering::Relaxed);
                self.inner
                    .validation_total_duration_ns
                    .fetch_add(duration_ns, Ordering::Relaxed);
            }
            "status_flusher" | "batch_flushed" => {
                self.inner.status_flushes.fetch_add(1, Ordering::Relaxed);
                self.inner
                    .status_flush_total_duration_ns
                    .fetch_add(duration_ns, Ordering::Relaxed);
            }
            "op.processed" | "op.finalized" => {
                self.inner.ops_processed.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        let mut stats = self
            .inner
            .span_stats
            .lock()
            .expect("SpanMetrics lock poisoned");
        stats
            .entry(span_name.to_string())
            .or_default()
            .record_end(duration_ns, errored);
    }

    // ========================================================================
    // Public accessors - General
    // ========================================================================

    /// Get total number of spans started.
    pub fn total_started(&self) -> u64 {
        self.inner.total_spans_started.load(Ordering::Relaxed)
    }

    /// Get total number of spans ended.
    pub fn total_ended(&self) -> u64 {
        self.inner.total_spans_ended.load(Ordering::Relaxed)
    }

    /// Get total number of spans that ended with error.
    pub fn total_errored(&self) -> u64 {
        self.inner.total_spans_errored.load(Ordering::Relaxed)
    }

    /// Get statistics for a specific span name.
    pub fn stats_for(&self, span_name: &str) -> Option<SpanStats> {
        let stats = self
            .inner
            .span_stats
            .lock()
            .expect("SpanMetrics lock poisoned");
        stats.get(span_name).cloned()
    }

    /// Get all span statistics.
    pub fn all_stats(&self) -> HashMap<String, SpanStats> {
        self.inner
            .span_stats
            .lock()
            .expect("SpanMetrics lock poisoned")
            .clone()
    }

    // ========================================================================
    // Public accessors - Batcher-specific (cached, lock-free)
    // ========================================================================

    /// Get cached batcher metrics (lock-free).
    pub fn batcher_metrics(&self) -> BatcherMetrics {
        let batches_completed = self.inner.batches_completed.load(Ordering::Relaxed);
        let batch_total_duration_ns = self.inner.batch_total_duration_ns.load(Ordering::Relaxed);

        BatcherMetrics {
            batches_started: self.inner.batches_started.load(Ordering::Relaxed),
            batches_completed,
            batches_failed: self.inner.batches_failed.load(Ordering::Relaxed),
            batch_total_duration_ns,
            batch_avg_duration_ns: if batches_completed > 0 {
                Some(batch_total_duration_ns / batches_completed)
            } else {
                None
            },
            validations_started: self.inner.validations_started.load(Ordering::Relaxed),
            validations_completed: self.inner.validations_completed.load(Ordering::Relaxed),
            validation_total_duration_ns: self
                .inner
                .validation_total_duration_ns
                .load(Ordering::Relaxed),
            status_flushes: self.inner.status_flushes.load(Ordering::Relaxed),
            status_flush_total_duration_ns: self
                .inner
                .status_flush_total_duration_ns
                .load(Ordering::Relaxed),
            ops_received: self.inner.ops_received.load(Ordering::Relaxed),
            ops_processed: self.inner.ops_processed.load(Ordering::Relaxed),
        }
    }

    /// Get number of batches started.
    pub fn batches_started(&self) -> u64 {
        self.inner.batches_started.load(Ordering::Relaxed)
    }

    /// Get number of batches completed successfully.
    pub fn batches_completed(&self) -> u64 {
        self.inner.batches_completed.load(Ordering::Relaxed)
    }

    /// Get number of batches that failed.
    pub fn batches_failed(&self) -> u64 {
        self.inner.batches_failed.load(Ordering::Relaxed)
    }

    /// Get total batch duration in nanoseconds.
    pub fn batch_total_duration_ns(&self) -> u64 {
        self.inner.batch_total_duration_ns.load(Ordering::Relaxed)
    }

    /// Get number of validation operations started.
    pub fn validations_started(&self) -> u64 {
        self.inner.validations_started.load(Ordering::Relaxed)
    }

    /// Get number of validation operations completed.
    pub fn validations_completed(&self) -> u64 {
        self.inner.validations_completed.load(Ordering::Relaxed)
    }

    /// Get number of operations received.
    pub fn ops_received(&self) -> u64 {
        self.inner.ops_received.load(Ordering::Relaxed)
    }

    /// Get number of operations processed.
    pub fn ops_processed(&self) -> u64 {
        self.inner.ops_processed.load(Ordering::Relaxed)
    }

    /// Snapshot the current state for reporting.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_started: self.total_started(),
            total_ended: self.total_ended(),
            total_errored: self.total_errored(),
            span_stats: self.all_stats(),
            batcher: self.batcher_metrics(),
        }
    }
}

impl Default for SpanMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// A snapshot of metrics at a point in time.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_started: u64,
    pub total_ended: u64,
    pub total_errored: u64,
    pub span_stats: HashMap<String, SpanStats>,
    pub batcher: BatcherMetrics,
}

// ============================================================================
// Metrics Span Processor
// ============================================================================

/// A SpanProcessor that records metrics on span lifecycle events.
///
/// This processor intercepts span start and end events to derive metrics
/// without requiring manual instrumentation. It's designed to be used
/// alongside other processors (like batch exporters).
///
/// # Metrics Derived
///
/// For each span name:
/// - Count of spans started
/// - Count of spans ended
/// - Count of spans with error status
/// - Total/min/max/avg duration
///
/// For batcher components specifically:
/// - batches_started/completed/failed
/// - validations_started/completed
/// - status_flushes
/// - ops_received/processed
///
/// # Thread Safety
///
/// This processor is thread-safe and can be cloned to share the underlying
/// metrics storage across components.
#[derive(Clone, Debug)]
pub struct MetricsSpanProcessor {
    metrics: SpanMetrics,
}

impl std::fmt::Debug for SpanMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpanMetrics")
            .field("total_started", &self.total_started())
            .field("total_ended", &self.total_ended())
            .field("total_errored", &self.total_errored())
            .field("batches_completed", &self.batches_completed())
            .field("ops_received", &self.ops_received())
            .finish()
    }
}

impl MetricsSpanProcessor {
    /// Create a new MetricsSpanProcessor.
    pub fn new(metrics: SpanMetrics) -> Self {
        Self { metrics }
    }

    /// Get a clone of the underlying metrics.
    pub fn metrics(&self) -> SpanMetrics {
        self.metrics.clone()
    }
}

impl SpanProcessor for MetricsSpanProcessor {
    fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, _cx: &opentelemetry::Context) {
        // The span name is available on the span data
        // For on_start, we need to extract the name differently
        // since the span hasn't been finalized yet
        if let Some(data) = span.exported_data() {
            self.metrics.on_start(data.name.as_ref());
        }
    }

    fn on_end(&self, span: SpanData) {
        // Calculate duration
        let duration_ns = span
            .end_time
            .duration_since(span.start_time)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Check if span has error status
        let errored = matches!(span.status, opentelemetry::trace::Status::Error { .. });

        self.metrics
            .on_end(span.name.as_ref(), duration_ns, errored);
    }

    fn force_flush(&self) -> opentelemetry::trace::TraceResult<()> {
        // No buffering, nothing to flush
        Ok(())
    }

    fn shutdown(&self) -> opentelemetry::trace::TraceResult<()> {
        // Log final metrics on shutdown
        let snapshot = self.metrics.snapshot();
        tracing::info!(
            total_started = snapshot.total_started,
            total_ended = snapshot.total_ended,
            total_errored = snapshot.total_errored,
            span_types = snapshot.span_stats.len(),
            "metrics_span_processor.shutdown"
        );

        // Log batcher-specific metrics
        let batcher = &snapshot.batcher;
        tracing::info!(
            batches_started = batcher.batches_started,
            batches_completed = batcher.batches_completed,
            batches_failed = batcher.batches_failed,
            batch_avg_duration_us = batcher.batch_avg_duration_ns.map(|n| n / 1000),
            validations_started = batcher.validations_started,
            validations_completed = batcher.validations_completed,
            ops_received = batcher.ops_received,
            ops_processed = batcher.ops_processed,
            "metrics_span_processor.batcher_stats"
        );

        // Log per-span stats
        for (name, stats) in &snapshot.span_stats {
            if stats.ended > 0 {
                tracing::debug!(
                    span_name = %name,
                    started = stats.started,
                    ended = stats.ended,
                    errored = stats.errored,
                    avg_duration_us = stats.avg_duration_ns().map(|n| n / 1000),
                    min_duration_us = stats.min_duration_ns.map(|n| n / 1000),
                    max_duration_us = stats.max_duration_ns.map(|n| n / 1000),
                    "metrics_span_processor.span_stats"
                );
            }
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_metrics_start_end() {
        let metrics = SpanMetrics::new();

        metrics.on_start("test_span");
        metrics.on_start("test_span");
        metrics.on_end("test_span", 1_000_000, false);
        metrics.on_end("test_span", 2_000_000, true);

        assert_eq!(metrics.total_started(), 2);
        assert_eq!(metrics.total_ended(), 2);
        assert_eq!(metrics.total_errored(), 1);

        let stats = metrics.stats_for("test_span").unwrap();
        assert_eq!(stats.started, 2);
        assert_eq!(stats.ended, 2);
        assert_eq!(stats.errored, 1);
        assert_eq!(stats.total_duration_ns, 3_000_000);
        assert_eq!(stats.min_duration_ns, Some(1_000_000));
        assert_eq!(stats.max_duration_ns, Some(2_000_000));
        assert_eq!(stats.avg_duration_ns(), Some(1_500_000));
    }

    #[test]
    fn test_span_metrics_multiple_names() {
        let metrics = SpanMetrics::new();

        metrics.on_start("batch");
        metrics.on_start("validation_worker");
        metrics.on_end("batch", 5_000_000, false);
        metrics.on_end("validation_worker", 1_000_000, false);

        let all = metrics.all_stats();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("batch"));
        assert!(all.contains_key("validation_worker"));
    }

    #[test]
    fn test_batcher_metrics_cached() {
        let metrics = SpanMetrics::new();

        // Simulate batch spans
        metrics.on_start("batch");
        metrics.on_start("batch");
        metrics.on_end("batch", 10_000_000, false);
        metrics.on_end("batch", 20_000_000, true);

        // Simulate validation spans
        metrics.on_start("validation_worker");
        metrics.on_end("validation_worker", 5_000_000, false);

        // Simulate op received
        metrics.on_start("op.received");

        let batcher = metrics.batcher_metrics();
        assert_eq!(batcher.batches_started, 2);
        assert_eq!(batcher.batches_completed, 1);
        assert_eq!(batcher.batches_failed, 1);
        assert_eq!(batcher.batch_total_duration_ns, 30_000_000);
        assert_eq!(batcher.batch_avg_duration_ns, Some(30_000_000)); // avg over 1 completed (total/completed)

        assert_eq!(batcher.validations_started, 1);
        assert_eq!(batcher.validations_completed, 1);
        assert_eq!(batcher.ops_received, 1);
    }

    #[test]
    fn test_span_metrics_snapshot() {
        let metrics = SpanMetrics::new();

        metrics.on_start("batch");
        metrics.on_end("batch", 100_000, false);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_started, 1);
        assert_eq!(snapshot.total_ended, 1);
        assert_eq!(snapshot.total_errored, 0);
        assert_eq!(snapshot.span_stats.len(), 1);
        assert_eq!(snapshot.batcher.batches_completed, 1);
    }
}
