//! Batched status updates for the request tracker.
//!
//! The `StatusBatcher` accumulates status updates and flushes them to the
//! `RequestTracker` either when a threshold is reached or after a time interval.
//! This avoids blocking the main driver loop on individual tracker updates.

use crate::request_tracker::RequestTracker;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::Instrument;
use world_id_core::types::GatewayRequestState;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the status batcher.
#[derive(Debug, Clone)]
pub struct StatusBatcherConfig {
    /// Number of updates before triggering a flush.
    pub flush_threshold: usize,
    /// Maximum time between flushes.
    pub flush_interval: Duration,
    /// Channel buffer size for flush batches.
    pub channel_buffer: usize,
}

impl Default for StatusBatcherConfig {
    fn default() -> Self {
        Self {
            flush_threshold: 64,
            flush_interval: Duration::from_millis(100),
            channel_buffer: 16,
        }
    }
}

// ============================================================================
// Status Update Types
// ============================================================================

/// A single status update to be batched.
#[derive(Debug, Clone)]
pub struct StatusUpdate {
    pub id: String,
    pub state: GatewayRequestState,
}

impl StatusUpdate {
    pub fn new(id: impl Into<String>, state: GatewayRequestState) -> Self {
        Self {
            id: id.into(),
            state,
        }
    }
}

// ============================================================================
// Status Batcher
// ============================================================================

/// Inner state of the status batcher (protected by mutex).
struct StatusBatcherInner {
    /// Pending updates waiting to be flushed.
    pending: Vec<StatusUpdate>,
    /// Last flush timestamp.
    last_flush: Instant,
}

/// Batches status updates and flushes them asynchronously.
///
/// The batcher accumulates updates in a local buffer and flushes them
/// either when the buffer reaches `flush_threshold` or when `flush_interval`
/// has elapsed since the last flush.
///
/// Flushing is non-blocking - updates are sent to a background task via a
/// channel. If the channel is full, updates are still accumulated locally.
///
/// This type is cloneable and thread-safe - clones share the same underlying
/// state and flush channel.
#[derive(Clone)]
pub struct StatusBatcher {
    /// Shared inner state.
    inner: Arc<Mutex<StatusBatcherInner>>,
    /// Configuration.
    config: StatusBatcherConfig,
    /// Sender for flush batches (to background flusher task).
    flush_tx: mpsc::Sender<Vec<StatusUpdate>>,
}

impl StatusBatcher {
    /// Create a new status batcher and spawn the background flusher task.
    ///
    /// Returns the batcher and a handle to the flusher task.
    pub fn new(
        tracker: Arc<RequestTracker>,
        config: StatusBatcherConfig,
    ) -> (Self, StatusFlusherHandle) {
        let (flush_tx, flush_rx) = mpsc::channel(config.channel_buffer);

        let flusher = StatusFlusher {
            tracker,
            rx: flush_rx,
        };

        let inner = StatusBatcherInner {
            pending: Vec::with_capacity(config.flush_threshold),
            last_flush: Instant::now(),
        };

        let batcher = Self {
            inner: Arc::new(Mutex::new(inner)),
            config,
            flush_tx,
        };

        (batcher, StatusFlusherHandle { flusher })
    }

    /// Push a status update to the pending buffer.
    ///
    /// This is a non-blocking, synchronous operation.
    #[inline]
    pub fn push(&self, update: StatusUpdate) {
        self.inner
            .lock()
            .expect("StatusBatcher lock poisoned")
            .pending
            .push(update);
    }

    /// Push a status update by ID and state.
    #[inline]
    pub fn push_status(&self, id: impl Into<String>, state: GatewayRequestState) {
        self.push(StatusUpdate::new(id, state));
    }

    /// Check if a flush is needed and trigger it if so.
    ///
    /// Returns `true` if a flush was triggered.
    /// This is a non-blocking operation - the actual flush happens asynchronously.
    pub fn maybe_flush(&self) -> bool {
        let mut inner = self.inner.lock().expect("StatusBatcher lock poisoned");
        let should_flush = inner.pending.len() >= self.config.flush_threshold
            || (!inner.pending.is_empty()
                && inner.last_flush.elapsed() >= self.config.flush_interval);

        if should_flush {
            self.flush_inner(&mut inner);
            true
        } else {
            false
        }
    }

    /// Force a flush of all pending updates.
    ///
    /// This is a non-blocking operation. Updates are sent to the background
    /// flusher task. If the channel is full, updates remain in the buffer.
    pub fn flush(&self) {
        let mut inner = self.inner.lock().expect("StatusBatcher lock poisoned");
        self.flush_inner(&mut inner);
    }

    /// Internal flush implementation (called with lock held).
    fn flush_inner(&self, inner: &mut StatusBatcherInner) {
        if inner.pending.is_empty() {
            return;
        }

        let batch = std::mem::take(&mut inner.pending);
        inner.pending = Vec::with_capacity(self.config.flush_threshold);

        // Try to send to the flusher - if full, updates are dropped
        // This is intentional: we prefer not blocking the main loop
        match self.flush_tx.try_send(batch) {
            Ok(()) => {
                inner.last_flush = Instant::now();
            }
            Err(mpsc::error::TrySendError::Full(batch)) => {
                // Put the updates back - we'll try again next time
                inner.pending = batch;
                tracing::warn!(
                    pending = inner.pending.len(),
                    "status_batcher.flush_channel_full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("status_batcher.flusher_disconnected");
            }
        }
    }

    /// Get the number of pending updates.
    #[inline]
    pub fn pending_count(&self) -> usize {
        self.inner
            .lock()
            .expect("StatusBatcher lock poisoned")
            .pending
            .len()
    }

    /// Check if there are pending updates.
    #[inline]
    pub fn has_pending(&self) -> bool {
        !self
            .inner
            .lock()
            .expect("StatusBatcher lock poisoned")
            .pending
            .is_empty()
    }
}

// ============================================================================
// Background Flusher
// ============================================================================

/// Handle for the background flusher task.
pub struct StatusFlusherHandle {
    flusher: StatusFlusher,
}

impl StatusFlusherHandle {
    /// Run the flusher as a background task.
    ///
    /// This should be spawned as a tokio task.
    pub async fn run(self) {
        self.flusher.run().await;
    }
}

/// Background task that receives batches and flushes them to the tracker.
struct StatusFlusher {
    tracker: Arc<RequestTracker>,
    rx: mpsc::Receiver<Vec<StatusUpdate>>,
}

impl StatusFlusher {
    async fn run(mut self) {
        let span = tracing::info_span!("status_flusher");

        async {
            tracing::debug!("status_flusher.started");

            while let Some(batch) = self.rx.recv().await {
                self.flush_batch(batch).await;
            }

            tracing::debug!("status_flusher.stopped");
        }
        .instrument(span)
        .await
    }

    async fn flush_batch(&self, batch: Vec<StatusUpdate>) {
        let count = batch.len();
        let start = Instant::now();

        for update in batch {
            self.tracker.set_status(&update.id, update.state).await;
        }

        let duration = start.elapsed();
        tracing::debug!(
            count,
            duration_us = duration.as_micros(),
            "status_flusher.batch_flushed"
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    async fn mock_tracker() -> Arc<RequestTracker> {
        Arc::new(RequestTracker::new(None).await)
    }

    #[tokio::test]
    async fn test_push_accumulates() {
        let tracker = mock_tracker().await;
        let (mut batcher, _handle) = StatusBatcher::new(tracker, StatusBatcherConfig::default());

        batcher.push_status("op1", GatewayRequestState::Queued);
        batcher.push_status("op2", GatewayRequestState::Queued);

        assert_eq!(batcher.pending_count(), 2);
    }

    #[tokio::test]
    async fn test_maybe_flush_threshold() {
        let tracker = mock_tracker().await;
        let config = StatusBatcherConfig {
            flush_threshold: 3,
            ..Default::default()
        };
        let (mut batcher, _handle) = StatusBatcher::new(tracker, config);

        batcher.push_status("op1", GatewayRequestState::Queued);
        batcher.push_status("op2", GatewayRequestState::Queued);
        assert!(!batcher.maybe_flush());

        batcher.push_status("op3", GatewayRequestState::Queued);
        assert!(batcher.maybe_flush());
        assert_eq!(batcher.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_flush_sends_to_channel() {
        let tracker = mock_tracker().await;
        let (mut batcher, handle) =
            StatusBatcher::new(tracker.clone(), StatusBatcherConfig::default());

        batcher.push_status("op1", GatewayRequestState::Queued);
        batcher.push_status("op2", GatewayRequestState::Queued);
        batcher.flush();

        assert_eq!(batcher.pending_count(), 0);

        // Run the flusher briefly
        tokio::select! {
            _ = handle.run() => {},
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }

        // Verify updates were processed (check tracker state)
        // Note: RequestTracker.get_status would need to be exposed for full verification
    }
}
