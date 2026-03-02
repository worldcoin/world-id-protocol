use std::{collections::VecDeque, time::Duration};

use tokio::{sync::mpsc, time::Instant};

use crate::{
    RequestTracker,
    batch_policy::{
        BacklogUrgencyStats, BaseFeeCache, BatchPolicyEngine, DecisionReason, record_policy_metrics,
    },
    config::BatchPolicyConfig,
    request_tracker::BacklogScope,
};

pub(crate) struct TimedEnvelope<T> {
    pub(crate) enqueued_at: Instant,
    pub(crate) envelope: T,
}

enum PolicyLoopEvent<T> {
    Tick,
    Recv(Option<T>),
}

/// Shared scheduler trait for gateway batchers.
///
/// Implementors provide batcher-specific primitives (queue source, submit path,
/// backlog scope, and no-backlog reconciliation), while this trait provides the
/// common policy event loop.
pub(crate) trait PolicyBatchLoopRunner {
    type Envelope: Send + 'static;

    /// Stable batch label used for logs/metrics (e.g. `"create"` or `"ops"`).
    fn batch_type(&self) -> &'static str;
    /// Redis backlog scope used when reading queued pressure for policy decisions.
    fn backlog_scope(&self) -> BacklogScope;
    /// Maximum batch size allowed for one on-chain submission.
    fn max_batch_size(&self) -> usize;
    /// In-memory local queue capacity before intake backpressure is applied.
    fn local_queue_limit(&self) -> usize;
    /// Batch policy configuration driving re-evaluation cadence and thresholds.
    fn batch_policy(&self) -> &BatchPolicyConfig;
    /// Shared base-fee cache consumed by the policy engine.
    fn base_fee_cache(&self) -> &BaseFeeCache;
    /// Request tracker used for queued backlog stats and request status updates.
    fn tracker(&self) -> &RequestTracker;
    /// Receiver from which new envelopes are pulled into the local queue.
    fn rx(&mut self) -> &mut mpsc::Receiver<Self::Envelope>;

    /// Sends a ready batch through the concrete batcher's on-chain submit path.
    async fn submit_batch(&self, batch: Vec<Self::Envelope>);
    /// Reconciles local queue state when Redis reports no backlog.
    ///
    /// This hook captures the intentional behavior difference:
    /// create clears queue and removes in-flight authenticators, while ops only clears queue.
    async fn handle_no_backlog(&self, queue: &mut VecDeque<TimedEnvelope<Self::Envelope>>);

    /// Policy-driven batching loop with periodic re-evaluation and bounded local queueing.
    async fn run_policy_loop(&mut self) {
        let mut policy_engine = BatchPolicyEngine::new(self.batch_policy().clone());
        let reeval_interval = Duration::from_millis(self.batch_policy().reeval_ms);

        let mut queue: VecDeque<TimedEnvelope<Self::Envelope>> = VecDeque::new();
        let mut next_eval = Instant::now() + reeval_interval;
        let mut rx_open = true;

        while rx_open || !queue.is_empty() {
            if queue.len() >= self.local_queue_limit() {
                tracing::warn!(
                    batch_type = self.batch_type(),
                    queue_len = queue.len(),
                    local_queue_limit = self.local_queue_limit(),
                    "{} policy queue reached local capacity, pausing intake for backpressure",
                    self.batch_type()
                );
            }

            if queue.is_empty() {
                if !rx_open {
                    break;
                }

                let maybe_first = {
                    let rx = self.rx();
                    rx.recv().await
                };
                match maybe_first {
                    Some(first) => {
                        queue.push_back(TimedEnvelope {
                            enqueued_at: Instant::now(),
                            envelope: first,
                        });
                        next_eval = Instant::now() + reeval_interval;
                    }
                    None => {
                        tracing::info!("{} batcher channel closed", self.batch_type());
                        rx_open = false;
                    }
                }
                continue;
            }

            let can_recv = rx_open && queue.len() < self.local_queue_limit();
            let event = {
                let rx = self.rx();
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(next_eval) => PolicyLoopEvent::Tick,
                    maybe_req = rx.recv(), if can_recv => PolicyLoopEvent::Recv(maybe_req),
                }
            };

            match event {
                PolicyLoopEvent::Tick => {
                    let cost_score =
                        policy_engine.update_cost_score(self.base_fee_cache().latest());

                    let fallback_age = queue
                        .front()
                        .map(|first| Instant::now().duration_since(first.enqueued_at).as_secs())
                        .unwrap_or_default();

                    let stats = match self
                        .tracker()
                        .queued_backlog_stats_for_scope(self.backlog_scope())
                        .await
                    {
                        Ok(stats) => stats,
                        Err(err) => {
                            tracing::warn!(
                                batch_type = self.batch_type(),
                                error = %err,
                                "failed to read queued backlog stats; using local fallback"
                            );
                            BacklogUrgencyStats {
                                queued_count: queue.len(),
                                oldest_age_secs: fallback_age,
                            }
                        }
                    };

                    let decision = policy_engine.evaluate(stats, self.max_batch_size(), cost_score);
                    record_policy_metrics(self.batch_type(), &decision);

                    if !decision.should_send {
                        if matches!(decision.reason, DecisionReason::NoBacklog) && !queue.is_empty()
                        {
                            self.handle_no_backlog(&mut queue).await;
                        }
                        next_eval = Instant::now() + reeval_interval;
                        continue;
                    }

                    let take_n = decision.target_batch_size.min(queue.len()).max(1);
                    let batch = queue.drain(..take_n).map(|timed| timed.envelope).collect();
                    self.submit_batch(batch).await;

                    next_eval = Instant::now() + reeval_interval;
                }
                PolicyLoopEvent::Recv(maybe_req) => match maybe_req {
                    Some(req) => {
                        queue.push_back(TimedEnvelope {
                            enqueued_at: Instant::now(),
                            envelope: req,
                        });
                    }
                    None => {
                        tracing::info!(
                            "{} batcher channel closed while policy batching",
                            self.batch_type()
                        );
                        rx_open = false;
                    }
                },
            }
        }
    }
}
