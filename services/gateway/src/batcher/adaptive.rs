use crate::batcher::types::ChainState;

/// Configuration for adaptive batch sizing
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Block gas limit
    pub block_gas_limit: u64,
    /// Estimated gas per operation
    pub gas_per_op: u64,
    /// Maximum base fee we'll pay (wei)
    pub max_base_fee: u64,
    /// Soft cap where we start being conservative (wei)
    pub soft_cap_base_fee: u64,
    /// Target base fee for comfortable operation (wei)
    pub target_base_fee: u64,
    /// Queue depth threshold for "backed up" state
    pub backlog_threshold: usize,
    /// Maximum operations per batch (hard cap)
    pub max_batch_ops: usize,
    /// Minimum operations per batch
    pub min_batch_ops: usize,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            block_gas_limit: 30_000_000,
            gas_per_op: 100_000,
            max_base_fee: 200_000_000_000,     // 200 gwei
            soft_cap_base_fee: 50_000_000_000, // 50 gwei
            target_base_fee: 20_000_000_000,   // 20 gwei
            backlog_threshold: 500,
            max_batch_ops: 100,
            min_batch_ops: 1,
        }
    }
}

impl AdaptiveConfig {
    /// Create config with values in gwei for convenience
    pub fn with_gwei(max_base_fee_gwei: u64, soft_cap_gwei: u64, target_gwei: u64) -> Self {
        Self {
            max_base_fee: max_base_fee_gwei * 1_000_000_000,
            soft_cap_base_fee: soft_cap_gwei * 1_000_000_000,
            target_base_fee: target_gwei * 1_000_000_000,
            ..Default::default()
        }
    }
}

/// Computes optimal batch size based on chain conditions and backlog.
///
/// Uses a pressure-based model where:
/// - Fee pressure (based on current base fee and trend) pushes toward smaller batches
/// - Queue pressure (based on backlog size) pushes toward larger batches
/// - Net pressure determines target block utilization
#[derive(Debug, Clone)]
pub struct AdaptiveSizer {
    config: AdaptiveConfig,
    /// Calibration factor for gas estimation (actual/estimated ratio)
    gas_calibration: f64,
}

impl AdaptiveSizer {
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            config,
            gas_calibration: 1.0,
        }
    }

    /// Update gas calibration based on actual vs estimated gas usage
    pub fn update_calibration(&mut self, estimated: u64, actual: u64) {
        if estimated == 0 {
            return;
        }
        let ratio = actual as f64 / estimated as f64;
        // Exponential moving average
        self.gas_calibration = self.gas_calibration * 0.9 + ratio * 0.1;
    }

    /// Get calibrated gas per operation
    pub fn calibrated_gas_per_op(&self) -> u64 {
        (self.config.gas_per_op as f64 * self.gas_calibration) as u64
    }

    /// Calculate fee pressure: how much the base fee is pushing against limits.
    ///
    /// Returns value in [0, 1] where:
    /// - 0 = base fee at or below target (no pressure)
    /// - 1 = base fee at or above ceiling (maximum pressure)
    pub fn fee_pressure(&self, base_fee: u64) -> f64 {
        if base_fee <= self.config.target_base_fee {
            0.0
        } else if base_fee >= self.config.max_base_fee {
            1.0
        } else {
            let range = self.config.max_base_fee - self.config.target_base_fee;
            (base_fee - self.config.target_base_fee) as f64 / range as f64
        }
    }

    /// Calculate queue pressure: how backed up are we.
    ///
    /// Returns value in [0, 1] where:
    /// - 0 = queue is empty
    /// - 1 = queue at or above threshold
    pub fn queue_pressure(&self, queue_depth: usize) -> f64 {
        if queue_depth == 0 {
            0.0
        } else {
            (queue_depth as f64 / self.config.backlog_threshold as f64).min(1.0)
        }
    }

    /// Calculate net pressure incorporating fee state, trend, and queue.
    ///
    /// Returns value in [-1, 1] where:
    /// - Negative = should increase batch size (queue pressure dominates)
    /// - Zero = balanced
    /// - Positive = should decrease batch size (fee pressure dominates)
    pub fn net_pressure(&self, chain: &ChainState, queue_depth: usize) -> f64 {
        let fee_p = self.fee_pressure(chain.base_fee);
        let queue_p = self.queue_pressure(queue_depth);

        // Fee pressure is amplified by positive trend (fees rising)
        // and dampened by negative trend (fees falling)
        let trend_factor = 1.0 + 0.5 * chain.base_fee_trend;
        let adjusted_fee_pressure = (fee_p * trend_factor).clamp(0.0, 1.0);

        // Net: fee pressure pushes us to do less, queue pressure pushes us to do more
        adjusted_fee_pressure - queue_p
    }

    /// Calculate target block utilization based on pressure.
    ///
    /// Maps net pressure to utilization:
    /// - pressure = -1 (max queue, no fee pressure) → utilization = 0.9
    /// - pressure =  0 (balanced)                   → utilization = 0.5
    /// - pressure = +1 (max fee pressure)           → utilization = 0.1
    pub fn target_utilization(&self, chain: &ChainState, queue_depth: usize) -> f64 {
        let pressure = self.net_pressure(chain, queue_depth);
        (0.5 - 0.4 * pressure).clamp(0.1, 0.9)
    }

    /// Calculate target gas budget for the next batch.
    pub fn target_gas(&self, chain: &ChainState, queue_depth: usize) -> u64 {
        let utilization = self.target_utilization(chain, queue_depth);
        (self.config.block_gas_limit as f64 * utilization) as u64
    }

    /// Calculate batch size for current conditions.
    ///
    /// This is the main entry point for batch sizing decisions.
    pub fn batch_size(&self, chain: &ChainState, queue_depth: usize) -> BatchSizeDecision {
        // Check ceiling
        if chain.base_fee >= self.config.max_base_fee {
            return BatchSizeDecision {
                batch_size: 0,
                gas_budget: 0,
                utilization_target: 0.0,
                fee_pressure: 1.0,
                queue_pressure: self.queue_pressure(queue_depth),
                net_pressure: 1.0,
                reason: BatchSizeReason::FeeCeiling,
            };
        }

        // Check empty queue
        if queue_depth == 0 {
            return BatchSizeDecision {
                batch_size: 0,
                gas_budget: 0,
                utilization_target: 0.0,
                fee_pressure: self.fee_pressure(chain.base_fee),
                queue_pressure: 0.0,
                net_pressure: self.fee_pressure(chain.base_fee),
                reason: BatchSizeReason::EmptyQueue,
            };
        }

        let fee_p = self.fee_pressure(chain.base_fee);
        let queue_p = self.queue_pressure(queue_depth);
        let net_p = self.net_pressure(chain, queue_depth);
        let utilization = self.target_utilization(chain, queue_depth);

        let gas_budget = (self.config.block_gas_limit as f64 * utilization) as u64;
        let gas_per_op = self.calibrated_gas_per_op();

        let ops_from_gas = (gas_budget / gas_per_op) as usize;

        // Apply bounds
        let batch_size = ops_from_gas
            .min(queue_depth)
            .min(self.config.max_batch_ops)
            .max(self.config.min_batch_ops);

        // Determine limiting factor
        let reason = if batch_size == self.config.max_batch_ops {
            BatchSizeReason::MaxBatchCap
        } else if batch_size == queue_depth {
            BatchSizeReason::QueueDrained
        } else if fee_p > 0.5 {
            BatchSizeReason::FeeConstrained
        } else {
            BatchSizeReason::Optimal
        };

        BatchSizeDecision {
            batch_size,
            gas_budget,
            utilization_target: utilization,
            fee_pressure: fee_p,
            queue_pressure: queue_p,
            net_pressure: net_p,
            reason,
        }
    }

    /// Project batch sizes over next N blocks (for planning/debugging)
    pub fn project(
        &self,
        initial_state: &ChainState,
        initial_queue: usize,
        blocks: usize,
        arrival_rate: f64,
    ) -> Vec<ProjectedBatch> {
        let mut projections = Vec::with_capacity(blocks);
        let mut state = initial_state.clone();
        let mut queue = initial_queue as f64;

        for i in 0..blocks {
            let decision = self.batch_size(&state, queue as usize);

            // Project base fee change based on our utilization
            let fee_multiplier = 1.0 + 0.125 * (2.0 * decision.utilization_target - 1.0);

            projections.push(ProjectedBatch {
                block_offset: i,
                batch_size: decision.batch_size,
                projected_base_fee: state.base_fee,
                projected_queue: queue as usize,
                utilization: decision.utilization_target,
            });

            // Update for next iteration
            state.base_fee = (state.base_fee as f64 * fee_multiplier) as u64;
            queue = (queue - decision.batch_size as f64 + arrival_rate).max(0.0);
            state.base_fee_trend = (fee_multiplier - 1.0) / 0.125;
        }

        projections
    }

    /// Get configuration
    pub fn config(&self) -> &AdaptiveConfig {
        &self.config
    }
}

/// Result of batch size calculation
#[derive(Debug, Clone)]
pub struct BatchSizeDecision {
    /// Number of operations to include
    pub batch_size: usize,
    /// Gas budget for this batch
    pub gas_budget: u64,
    /// Target block utilization (0-1)
    pub utilization_target: f64,
    /// Current fee pressure (0-1)
    pub fee_pressure: f64,
    /// Current queue pressure (0-1)
    pub queue_pressure: f64,
    /// Net pressure signal (-1 to 1)
    pub net_pressure: f64,
    /// Why this size was chosen
    pub reason: BatchSizeReason,
}

/// Reason for batch size decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchSizeReason {
    /// Optimal based on pressure balance
    Optimal,
    /// Limited by max batch size config
    MaxBatchCap,
    /// Limited by queue depth
    QueueDrained,
    /// Reduced due to fee pressure
    FeeConstrained,
    /// Not batching because at fee ceiling
    FeeCeiling,
    /// Not batching because queue is empty
    EmptyQueue,
}

/// Projected batch for future block
#[derive(Debug, Clone)]
pub struct ProjectedBatch {
    pub block_offset: usize,
    pub batch_size: usize,
    pub projected_base_fee: u64,
    pub projected_queue: usize,
    pub utilization: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn make_chain_state(base_fee_gwei: u64, trend: f64) -> ChainState {
        ChainState {
            block_number: 1,
            base_fee: base_fee_gwei * 1_000_000_000,
            base_fee_ema: base_fee_gwei as f64 * 1_000_000_000.0,
            base_fee_trend: trend,
            block_gas_limit: 30_000_000,
            recent_utilization: 0.5,
            last_updated: Instant::now().into(),
        }
    }

    #[test]
    fn test_low_fee_high_queue_aggressive() {
        let sizer = AdaptiveSizer::new(AdaptiveConfig::default());
        let state = make_chain_state(10, 0.0); // 10 gwei, stable

        let decision = sizer.batch_size(&state, 1000);

        assert!(decision.utilization_target > 0.7);
        assert!(decision.batch_size > 50);
        assert!(decision.net_pressure < 0.0);
    }

    #[test]
    fn test_high_fee_low_queue_conservative() {
        let sizer = AdaptiveSizer::new(AdaptiveConfig::default());
        let state = make_chain_state(100, 0.0); // 100 gwei

        let decision = sizer.batch_size(&state, 10);

        assert!(decision.utilization_target < 0.4);
        assert!(decision.net_pressure > 0.0);
    }

    #[test]
    fn test_fee_ceiling_stops_batching() {
        let sizer = AdaptiveSizer::new(AdaptiveConfig::default());
        let state = make_chain_state(250, 0.0); // Above 200 gwei ceiling

        let decision = sizer.batch_size(&state, 1000);

        assert_eq!(decision.batch_size, 0);
        assert_eq!(decision.reason, BatchSizeReason::FeeCeiling);
    }

    #[test]
    fn test_rising_trend_more_conservative() {
        let sizer = AdaptiveSizer::new(AdaptiveConfig::default());

        let rising = make_chain_state(50, 0.5); // Rising trend
        let falling = make_chain_state(50, -0.5); // Falling trend

        let rising_decision = sizer.batch_size(&rising, 500);
        let falling_decision = sizer.batch_size(&falling, 500);

        // Rising fees should result in smaller batches
        assert!(rising_decision.batch_size < falling_decision.batch_size);
    }

    #[test]
    fn test_projection_clears_queue() {
        let sizer = AdaptiveSizer::new(AdaptiveConfig::default());
        let state = make_chain_state(15, 0.0);

        let projections = sizer.project(&state, 200, 20, 5.0);

        // Should make progress on clearing queue
        let final_queue = projections.last().unwrap().projected_queue;
        assert!(final_queue < 200);
    }

    #[test]
    fn test_gas_calibration() {
        let mut sizer = AdaptiveSizer::new(AdaptiveConfig::default());

        // Simulate actual gas being 20% higher than estimated
        for _ in 0..10 {
            sizer.update_calibration(100_000, 120_000);
        }

        // Calibrated gas should be higher
        assert!(sizer.calibrated_gas_per_op() > sizer.config.gas_per_op);
    }
}
