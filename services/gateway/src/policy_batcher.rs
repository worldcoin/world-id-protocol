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

/// Shared loop configuration used by both legacy and policy modes.
pub(crate) struct BatchLoopConfig<T> {
    pub(crate) batch_type: &'static str,
    pub(crate) backlog_scope: BacklogScope,
    pub(crate) max_batch_size: usize,
    pub(crate) local_queue_limit: usize,
    pub(crate) batch_policy: BatchPolicyConfig,
    pub(crate) base_fee_cache: BaseFeeCache,
    pub(crate) tracker: RequestTracker,
    pub(crate) rx: mpsc::Receiver<T>,
}

impl<T> BatchLoopConfig<T> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        batch_type: &'static str,
        backlog_scope: BacklogScope,
        max_batch_size: usize,
        local_queue_limit: usize,
        batch_policy: BatchPolicyConfig,
        base_fee_cache: BaseFeeCache,
        tracker: RequestTracker,
        rx: mpsc::Receiver<T>,
    ) -> Self {
        Self {
            batch_type,
            backlog_scope,
            max_batch_size,
            local_queue_limit: local_queue_limit.max(1),
            batch_policy,
            base_fee_cache,
            tracker,
            rx,
        }
    }
}

enum PolicyLoopEvent<T> {
    Tick,
    Recv(Option<T>),
}

/// Batcher-specific hooks consumed by the shared scheduling loops.
pub(crate) trait BatchLoopHooks {
    type Envelope: Send + 'static;

    /// Sends a ready batch through the concrete batcher's on-chain submit path.
    async fn submit_batch(&self, tracker: &RequestTracker, batch: Vec<Self::Envelope>);

    /// Reconciles local queue state when Redis reports no backlog.
    ///
    /// This hook captures the intentional behavior difference:
    /// create clears queue and removes in-flight authenticators, while ops only clears queue.
    async fn handle_no_backlog(
        &self,
        tracker: &RequestTracker,
        queue: &mut VecDeque<TimedEnvelope<Self::Envelope>>,
    );
}

/// Legacy batching loop: wait for first request, then fill until deadline or max batch size.
pub(crate) async fn run_legacy_loop<H>(cfg: &mut BatchLoopConfig<H::Envelope>, hooks: &H)
where
    H: BatchLoopHooks,
{
    let window = Duration::from_millis(cfg.batch_policy.reeval_ms);

    loop {
        let first = cfg.rx.recv().await;
        let Some(first) = first else {
            tracing::info!("{} batcher channel closed", cfg.batch_type);
            return;
        };

        let mut batch = vec![first];
        let deadline = Instant::now() + window;

        loop {
            if batch.len() >= cfg.max_batch_size {
                break;
            }

            let next_req = tokio::time::timeout_at(deadline, cfg.rx.recv()).await;
            match next_req {
                Ok(Some(req)) => batch.push(req),
                Ok(None) => {
                    tracing::info!("{} batcher channel closed while batching", cfg.batch_type);
                    break;
                }
                Err(_) => break, // Timeout expired
            }
        }

        hooks.submit_batch(&cfg.tracker, batch).await;
    }
}

/// Policy-driven batching loop with periodic re-evaluation and bounded local queueing.
pub(crate) async fn run_policy_loop<H>(cfg: &mut BatchLoopConfig<H::Envelope>, hooks: &H)
where
    H: BatchLoopHooks,
{
    let mut policy_engine = BatchPolicyEngine::new(cfg.batch_policy.clone());
    let reeval_interval = Duration::from_millis(cfg.batch_policy.reeval_ms);

    let mut queue: VecDeque<TimedEnvelope<H::Envelope>> = VecDeque::new();
    let mut next_eval = Instant::now() + reeval_interval;
    let mut rx_open = true;

    while rx_open || !queue.is_empty() {
        if queue.len() >= cfg.local_queue_limit {
            tracing::warn!(
                batch_type = cfg.batch_type,
                queue_len = queue.len(),
                local_queue_limit = cfg.local_queue_limit,
                "{} policy queue reached local capacity, pausing intake for backpressure",
                cfg.batch_type
            );
        }

        if queue.is_empty() {
            if !rx_open {
                break;
            }

            let maybe_first = cfg.rx.recv().await;
            match maybe_first {
                Some(first) => {
                    queue.push_back(TimedEnvelope {
                        enqueued_at: Instant::now(),
                        envelope: first,
                    });
                    next_eval = Instant::now() + reeval_interval;
                }
                None => {
                    tracing::info!("{} batcher channel closed", cfg.batch_type);
                    rx_open = false;
                }
            }
            continue;
        }

        let can_recv = rx_open && queue.len() < cfg.local_queue_limit;
        let event = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(next_eval) => PolicyLoopEvent::Tick,
            maybe_req = cfg.rx.recv(), if can_recv => PolicyLoopEvent::Recv(maybe_req),
        };

        match event {
            PolicyLoopEvent::Tick => {
                let cost_score = policy_engine.update_cost_score(cfg.base_fee_cache.latest());

                let fallback_age = queue
                    .front()
                    .map(|first| Instant::now().duration_since(first.enqueued_at).as_secs())
                    .unwrap_or_default();

                let stats = match cfg
                    .tracker
                    .queued_backlog_stats_for_scope(cfg.backlog_scope)
                    .await
                {
                    Ok(stats) => stats,
                    Err(err) => {
                        tracing::warn!(
                            batch_type = cfg.batch_type,
                            error = %err,
                            "failed to read queued backlog stats; using local fallback"
                        );
                        BacklogUrgencyStats {
                            queued_count: queue.len(),
                            oldest_age_secs: fallback_age,
                        }
                    }
                };

                let decision = policy_engine.evaluate(stats, cfg.max_batch_size, cost_score);
                record_policy_metrics(cfg.batch_type, &decision);

                if !decision.should_send {
                    if matches!(decision.reason, DecisionReason::NoBacklog) && !queue.is_empty() {
                        hooks.handle_no_backlog(&cfg.tracker, &mut queue).await;
                    }
                    next_eval = Instant::now() + reeval_interval;
                    continue;
                }

                let take_n = decision.target_batch_size.min(queue.len()).max(1);
                let batch = queue.drain(..take_n).map(|timed| timed.envelope).collect();
                hooks.submit_batch(&cfg.tracker, batch).await;

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
                        cfg.batch_type
                    );
                    rx_open = false;
                }
            },
        }
    }
}
