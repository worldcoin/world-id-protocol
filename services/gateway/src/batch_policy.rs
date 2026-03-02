use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use alloy::{
    eips::BlockNumberOrTag,
    providers::{DynProvider, Provider},
};

use crate::{
    config::BatchPolicyConfig,
    metrics::{
        METRICS_BATCH_POLICY_COST_SCORE, METRICS_BATCH_POLICY_DEFER,
        METRICS_BATCH_POLICY_FORCE_SEND, METRICS_BATCH_POLICY_TARGET_SIZE,
        METRICS_BATCH_POLICY_URGENCY_SCORE,
    },
};

/// Aggregated queued backlog pressure from Redis.
#[derive(Debug, Clone, Copy, Default)]
pub struct BacklogUrgencyStats {
    pub queued_count: usize,
    pub oldest_age_secs: u64,
}

/// Shared cache of latest base fee used by policy loops.
#[derive(Clone, Default)]
pub struct BaseFeeCache {
    inner: Arc<RwLock<Option<u128>>>,
}

impl BaseFeeCache {
    pub fn latest(&self) -> Option<u128> {
        match self.inner.read() {
            Ok(guard) => *guard,
            Err(_) => None,
        }
    }

    fn set_latest(&self, value: Option<u128>) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = value;
        }
    }
}

/// Policy decision produced by [`BatchPolicyEngine::evaluate`] for one scheduler tick.
///
/// This is the complete contract consumed by batcher loops:
/// - `should_send = false`: keep queued requests in memory and retry at next re-evaluation tick.
/// - `should_send = true`: pop up to `target_batch_size` and submit on-chain now.
/// - `force_send = true`: this dispatch is mandatory (`max_wait_secs` reached), so cost pressure
///   must not defer it.
///
/// `cost_score` and `urgency_score` are included in the decision for observability (metrics/logs)
/// and to simplify debugging/tuning of threshold choices.
#[derive(Debug, Clone, Copy)]
pub struct PolicyDecision {
    pub should_send: bool,
    pub force_send: bool,
    pub target_batch_size: usize,
    pub cost_score: f64,
    pub urgency_score: f64,
    pub reason: DecisionReason,
}

/// Reason tag for policy outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    NoBacklog,
    SendLowCostMaxBatch,
    ForceMaxWait,
    DeferHighCostLowUrgency,
    SendHighCostHighUrgency,
}

impl DecisionReason {
    /// Convert enum variants into static str.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoBacklog => "no_backlog",
            Self::SendLowCostMaxBatch => "send_low_cost_max_batch",
            Self::ForceMaxWait => "force_max_wait",
            Self::DeferHighCostLowUrgency => "defer_high_cost_low_urgency",
            Self::SendHighCostHighUrgency => "send_cost_high_but_urgent",
        }
    }
}

/// Runtime evaluator for adaptive batching decisions.
pub struct BatchPolicyEngine {
    cfg: BatchPolicyConfig,
    ema_base_fee: Option<f64>,
}

impl BatchPolicyEngine {
    pub fn new(cfg: BatchPolicyConfig) -> Self {
        Self {
            cfg,
            ema_base_fee: None,
        }
    }

    /// Evaluate whether to send now and what batch size to target.
    ///
    /// Decision flow (in strict execution order):
    /// 1. Compute `urgency_score` from queued age/size pressure.
    /// 2. If there is no backlog, return `NoBacklog` and do nothing.
    /// 3. Check hard `max_wait_secs`: if oldest queued age reached it, return `ForceMaxWait`.
    /// 4. Compute whether current chain cost is high (`cost_score >= cost_high_ratio`).
    /// 5. If chain cost is not high, send immediately with max batch size.
    /// 6. If chain cost is high, derive a reduced batch size from urgency.
    /// 7. Under high cost, defer unless urgency is high (`urgency_score >= 1.0`).
    ///
    /// This ordering makes latency SLOs win over gas optimization:
    /// hard max wait can always force dispatch regardless of cost pressure.
    pub fn evaluate(
        &self,
        stats: BacklogUrgencyStats,
        max_batch_size: usize,
        cost_score: f64,
    ) -> PolicyDecision {
        // Step 1: derive urgency from backlog pressure.
        let urgency_score = self.urgency_score(stats);
        let has_backlog = stats.queued_count > 0;
        let force_send = has_backlog && stats.oldest_age_secs >= self.cfg.max_wait_secs;
        let max_batch_size = max_batch_size.max(1);

        // Step 2: no queued work means no action.
        if !has_backlog {
            return PolicyDecision {
                should_send: false,
                force_send: false,
                target_batch_size: 0,
                cost_score,
                urgency_score,
                reason: DecisionReason::NoBacklog,
            };
        }

        // Step 3: hard max-wait guardrail overrides all cost-driven behavior.
        if force_send {
            return PolicyDecision {
                should_send: true,
                force_send: true,
                target_batch_size: max_batch_size,
                cost_score,
                urgency_score,
                reason: DecisionReason::ForceMaxWait,
            };
        }

        // Step 4: classify cost pressure.
        let cost_high = cost_score >= self.cfg.cost_high_ratio;

        // Step 5: cheap chain conditions => maximize throughput.
        if !cost_high {
            return PolicyDecision {
                should_send: true,
                force_send: false,
                target_batch_size: max_batch_size,
                cost_score,
                urgency_score,
                reason: DecisionReason::SendLowCostMaxBatch,
            };
        }

        // Step 6: high-cost path derives a reduced batch size from urgency.
        let target_batch_size = high_cost_target_batch_size(max_batch_size, urgency_score);

        // Step 7: high-cost path defers unless urgency is truly high.
        if urgency_score < 1.0 {
            return PolicyDecision {
                should_send: false,
                force_send: false,
                target_batch_size,
                cost_score,
                urgency_score,
                reason: DecisionReason::DeferHighCostLowUrgency,
            };
        }

        // Step 7 (continue): high urgency under high cost still sends.
        PolicyDecision {
            should_send: true,
            force_send: false,
            target_batch_size,
            cost_score,
            urgency_score,
            reason: DecisionReason::SendHighCostHighUrgency,
        }
    }

    /// Update cost state with latest base fee and return current cost score.
    ///
    /// Formula:
    /// - `cost_score_t = latest_base_fee_t / ema_base_fee_(t-1)`
    /// - `ema_base_fee_t = alpha * latest_base_fee_t + (1 - alpha) * ema_base_fee_(t-1)`
    ///
    /// Initialization:
    /// - On first sample there is no prior EMA, so we set `ema_base_fee = latest_base_fee`
    ///   and return `cost_score = 1.0` (neutral baseline).
    ///
    /// Fallback behavior:
    /// - Missing/zero/invalid input yields `1.0`, so cost pressure does not trigger deferral.
    pub fn update_cost_score(&mut self, latest_base_fee_wei: Option<u128>) -> f64 {
        let Some(latest) = latest_base_fee_wei else {
            return 1.0;
        };
        if latest == 0 {
            return 1.0;
        }

        let latest_f = latest as f64;
        let score = self
            .ema_base_fee
            .filter(|ema| *ema > 0.0)
            .map(|ema| latest_f / ema)
            .unwrap_or(1.0);

        self.ema_base_fee = Some(match self.ema_base_fee {
            Some(prev) => {
                self.cfg.cost_ema_alpha * latest_f + (1.0 - self.cfg.cost_ema_alpha) * prev
            }
            None => latest_f,
        });

        if score.is_finite() && score > 0.0 {
            score
        } else {
            1.0
        }
    }

    /// Compute urgency as a weighted blend of age pressure and size pressure.
    ///
    /// Formula:
    /// - `age_pressure = oldest_age_secs / max_wait_secs`
    /// - `size_pressure = queued_count / backlog_high_watermark`
    /// - `urgency_score = 0.7 * clamp(age_pressure, 0..2) + 0.3 * clamp(size_pressure, 0..2)`
    ///
    /// Intuition:
    /// - Age dominates (70%) because old requests are the strongest "send now" signal.
    /// - Size contributes (30%) to react faster when backlog volume grows quickly.
    /// - Clamping to `[0, 2]` bounds outliers and keeps thresholds stable.
    ///
    /// Operational thresholds used by `evaluate`:
    /// - `< 0.5` low urgency
    /// - `0.5..1.0` medium urgency
    /// - `>= 1.0` high urgency
    fn urgency_score(&self, stats: BacklogUrgencyStats) -> f64 {
        if stats.queued_count == 0 {
            return 0.0;
        }

        let age_pressure = if self.cfg.max_wait_secs == 0 {
            0.0
        } else {
            stats.oldest_age_secs as f64 / self.cfg.max_wait_secs as f64
        };
        let size_pressure = if self.cfg.backlog_high_watermark == 0 {
            0.0
        } else {
            stats.queued_count as f64 / self.cfg.backlog_high_watermark as f64
        };

        // Weighted blend where age pressure dominates.
        0.7 * clamp_0_2(age_pressure) + 0.3 * clamp_0_2(size_pressure)
    }
}

/// Emits policy metrics for a decision.
pub fn record_policy_metrics(batch_type: &'static str, decision: &PolicyDecision) {
    ::metrics::histogram!(METRICS_BATCH_POLICY_COST_SCORE, "type" => batch_type)
        .record(decision.cost_score);
    ::metrics::histogram!(METRICS_BATCH_POLICY_URGENCY_SCORE, "type" => batch_type)
        .record(decision.urgency_score);
    ::metrics::histogram!(METRICS_BATCH_POLICY_TARGET_SIZE, "type" => batch_type)
        .record(decision.target_batch_size as f64);

    if decision.force_send {
        ::metrics::counter!(METRICS_BATCH_POLICY_FORCE_SEND, "type" => batch_type).increment(1);
    }

    if !decision.should_send {
        ::metrics::counter!(
            METRICS_BATCH_POLICY_DEFER,
            "type" => batch_type,
            "reason" => decision.reason.as_str()
        )
        .increment(1);
    }
}

fn clamp_0_2(v: f64) -> f64 {
    if !v.is_finite() || v <= 0.0 {
        0.0
    } else if v > 2.0 {
        2.0
    } else {
        v
    }
}

fn high_cost_target_batch_size(max_batch_size: usize, urgency_score: f64) -> usize {
    // Under high chain cost:
    // - urgency >= 1.0 -> 50% batch
    // - urgency < 1.0 -> 25% batch
    let ratio = if urgency_score >= 1.0 { 0.5 } else { 0.25 };
    ((max_batch_size as f64) * ratio).ceil() as usize
}

/// Spawn a background task that refreshes latest base fee in a shared cache.
pub fn spawn_base_fee_sampler(
    provider: Arc<DynProvider>,
    interval: Duration,
    cache: BaseFeeCache,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let fee = latest_base_fee_wei(provider.as_ref()).await;
            cache.set_latest(fee);
        }
    })
}

/// Fetch latest block base fee. Returns `None` for chains without EIP-1559
/// base fee support or when RPC calls fail.
async fn latest_base_fee_wei(provider: &DynProvider) -> Option<u128> {
    let fee_history = provider
        .get_fee_history(1, BlockNumberOrTag::Latest, &[])
        .await
        .ok()?;
    fee_history.latest_block_base_fee()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BatchPolicyConfig {
        BatchPolicyConfig {
            reeval_ms: 2_000,
            max_wait_secs: 30,
            cost_ema_alpha: 0.2,
            cost_high_ratio: 1.2,
            backlog_high_watermark: 200,
        }
    }

    #[test]
    fn defer_when_cost_high_and_urgency_low() {
        let engine = BatchPolicyEngine::new(cfg());
        let stats = BacklogUrgencyStats {
            queued_count: 4,
            oldest_age_secs: 2,
        };
        let decision = engine.evaluate(stats, 100, 1.5);
        assert!(!decision.should_send);
        assert_eq!(decision.reason, DecisionReason::DeferHighCostLowUrgency);
    }

    #[test]
    fn defer_when_cost_high_and_urgency_medium() {
        let engine = BatchPolicyEngine::new(cfg());
        let stats = BacklogUrgencyStats {
            queued_count: 80,
            oldest_age_secs: 21,
        };
        let decision = engine.evaluate(stats, 100, 1.5);
        assert!(!decision.should_send);
        assert_eq!(decision.target_batch_size, 25);
    }

    #[test]
    fn force_send_at_max_wait() {
        let engine = BatchPolicyEngine::new(cfg());
        let stats = BacklogUrgencyStats {
            queued_count: 10,
            oldest_age_secs: 30,
        };
        let decision = engine.evaluate(stats, 100, 2.0);
        assert!(decision.should_send);
        assert!(decision.force_send);
        assert_eq!(decision.target_batch_size, 100);
        assert_eq!(decision.reason, DecisionReason::ForceMaxWait);
    }

    #[test]
    fn batch_size_tiering_applies() {
        let engine = BatchPolicyEngine::new(cfg());

        let low = engine.evaluate(
            BacklogUrgencyStats {
                queued_count: 1,
                oldest_age_secs: 1,
            },
            100,
            1.0,
        );
        assert_eq!(low.target_batch_size, 100);

        let medium = engine.evaluate(
            BacklogUrgencyStats {
                queued_count: 100,
                oldest_age_secs: 15,
            },
            100,
            1.0,
        );
        assert_eq!(medium.target_batch_size, 100);

        let high = engine.evaluate(
            BacklogUrgencyStats {
                queued_count: 500,
                oldest_age_secs: 20,
            },
            100,
            1.0,
        );
        assert_eq!(high.target_batch_size, 100);

        let high_cost_low_urgency = engine.evaluate(
            BacklogUrgencyStats {
                queued_count: 2,
                oldest_age_secs: 1,
            },
            100,
            1.5,
        );
        assert!(!high_cost_low_urgency.should_send);
        assert_eq!(high_cost_low_urgency.target_batch_size, 25);

        let high_cost_medium_urgency = engine.evaluate(
            BacklogUrgencyStats {
                queued_count: 80,
                oldest_age_secs: 21,
            },
            100,
            1.5,
        );
        assert!(!high_cost_medium_urgency.should_send);
        assert_eq!(high_cost_medium_urgency.target_batch_size, 25);

        let high_cost_high_urgency = engine.evaluate(
            BacklogUrgencyStats {
                queued_count: 300,
                oldest_age_secs: 29,
            },
            100,
            1.5,
        );
        assert!(high_cost_high_urgency.should_send);
        assert_eq!(high_cost_high_urgency.target_batch_size, 50);
    }
}
