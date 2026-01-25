use crate::batcher::chain::ChainState;

/// Trait for gas policy implementations.
///
/// Allows different gas strategies to be plugged into the batcher.
pub trait GasPolicyTrait: Send + Sync + 'static {
    /// Compute batch parameters based on current chain state and queue depth.
    fn compute_batch_params(&self, chain: &ChainState, queue_depth: usize) -> BatchParameters;
}

/// Configuration for adaptive batch sizing
#[derive(Debug, Clone)]
pub struct GasPolicyConfig {
    /// Block gas limit
    pub block_gas_limit: u64,
    /// Maximum base fee we'll pay (wei)
    pub max_base_fee: u64,
    /// Target base fee for comfortable operation (wei)
    pub target_base_fee: u64,
    /// Queue depth threshold for "backed up" state
    pub backlog_threshold: usize,
}

impl Default for GasPolicyConfig {
    fn default() -> Self {
        Self {
            block_gas_limit: 100_000_000,
            max_base_fee: 4_000_000_000, // 4 gwei
            target_base_fee: 1,
            backlog_threshold: 2_000,
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
pub struct GasPolicy {
    config: GasPolicyConfig,
}

impl GasPolicy {
    pub fn new(config: GasPolicyConfig) -> Self {
        Self { config }
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

    /// Compute batch parameters based on current chain state and queue depth.
    fn compute_batch_params_inner(
        &self,
        chain: &ChainState,
        queue_depth: usize,
    ) -> BatchParameters {
        // Check ceiling
        if chain.base_fee >= self.config.max_base_fee {
            return BatchParameters {
                gas_budget: 0,
                reason: BatchSizeReason::FeeCeiling,
            };
        }

        let fee_p = self.fee_pressure(chain.base_fee);
        let utilization = self.target_utilization(chain, queue_depth);

        let gas_budget = (self.config.block_gas_limit as f64 * utilization) as u64;

        // Determine limiting factor
        let reason = if fee_p > 0.5 {
            BatchSizeReason::FeeConstrained
        } else {
            BatchSizeReason::Optimal
        };

        BatchParameters { gas_budget, reason }
    }
}

impl GasPolicyTrait for GasPolicy {
    fn compute_batch_params(&self, chain: &ChainState, queue_depth: usize) -> BatchParameters {
        self.compute_batch_params_inner(chain, queue_depth)
    }
}

/// Result of batch size calculation
#[derive(Debug, Clone)]
pub struct BatchParameters {
    /// Gas budget for this batch
    pub gas_budget: u64,
    /// Why this size was chosen
    pub reason: BatchSizeReason,
}

impl std::fmt::Display for BatchParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BatchParameters {{ gas_budget: {}, reason: {:?} }}",
            self.gas_budget, self.reason
        )
    }
}

/// Reason for batch size decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchSizeReason {
    /// Optimal based on pressure balance
    Optimal,
    /// Reduced due to fee pressure
    FeeConstrained,
    /// Not batching because at fee ceiling
    FeeCeiling,
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
    fn test_gas_policy_pressure_model() {
        let config = GasPolicyConfig {
            block_gas_limit: 100_000_000,
            max_base_fee: 400_000_000_000, // 400 gwei
            target_base_fee: 0,
            backlog_threshold: 2_000,
        };
        let policy = GasPolicy::new(config);

        // --- Fee Pressure ---
        // At or below target: 0
        assert_eq!(policy.fee_pressure(0), 0.0);
        // Mid-range: linear interpolation
        assert!((policy.fee_pressure(200_000_000_000) - 0.5).abs() < 0.001);
        // At max: 1
        assert_eq!(policy.fee_pressure(400_000_000_000), 1.0);
        // Above max: clamped to 1
        assert_eq!(policy.fee_pressure(500_000_000_000), 1.0);

        // --- Queue Pressure ---
        // Empty queue: 0
        assert_eq!(policy.queue_pressure(0), 0.0);
        // Half full: 0.5
        assert!((policy.queue_pressure(1_000) - 0.5).abs() < 0.001);
        // At threshold: 1
        assert_eq!(policy.queue_pressure(2_000), 1.0);
        // Above threshold: clamped to 1
        assert_eq!(policy.queue_pressure(5_000), 1.0);

        // --- Net Pressure & Target Utilization ---
        // Max queue pressure, no fee pressure → net = -1 → utilization = 0.9
        let chain_cheap = make_chain_state(0, 0.0);
        assert!((policy.net_pressure(&chain_cheap, 2_000) - (-1.0)).abs() < 0.001);
        assert!((policy.target_utilization(&chain_cheap, 2_000) - 0.9).abs() < 0.001);

        // No queue, max fee pressure → net = 1 → utilization = 0.1
        let chain_expensive = make_chain_state(400, 0.0);
        assert!((policy.net_pressure(&chain_expensive, 0) - 1.0).abs() < 0.001);
        assert!((policy.target_utilization(&chain_expensive, 0) - 0.1).abs() < 0.001);

        // Balanced: mid fee, mid queue → net ≈ 0 → utilization ≈ 0.5
        let chain_mid = make_chain_state(200, 0.0);
        assert!(policy.net_pressure(&chain_mid, 1_000).abs() < 0.001);
        assert!((policy.target_utilization(&chain_mid, 1_000) - 0.5).abs() < 0.001);

        // Rising trend amplifies fee pressure
        let chain_rising = make_chain_state(200, 1.0);
        let net_rising = policy.net_pressure(&chain_rising, 1_000);
        assert!(
            net_rising > 0.0,
            "rising trend should tip toward fee pressure"
        );

        // --- Gas Budget Computation ---
        // Cheap gas, full queue → 90% utilization → 90M gas
        let params = policy.compute_batch_params(&chain_cheap, 2_000);
        assert_eq!(params.gas_budget, 90_000_000);
        assert_eq!(params.reason, BatchSizeReason::Optimal);

        // Expensive gas, empty queue → 10% utilization → 10M gas
        let chain_high_fee = make_chain_state(399, 0.0);
        let params = policy.compute_batch_params(&chain_high_fee, 0);
        assert!(
            params.gas_budget <= 15_000_000,
            "high fee should yield low budget"
        );
        assert_eq!(params.reason, BatchSizeReason::FeeConstrained);

        // Fee ceiling → budget = 0
        let params = policy.compute_batch_params(&chain_expensive, 2_000);
        assert_eq!(params.gas_budget, 0);
        assert_eq!(params.reason, BatchSizeReason::FeeCeiling);
    }
}
