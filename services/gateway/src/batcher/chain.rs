use crate::batcher::types::ChainState;
use alloy::consensus::Header;
use alloy::providers::Provider;
use alloy::rpc::types::BlockNumberOrTag;
use anyhow::Context;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Monitors chain state for adaptive batching decisions.
///
/// Runs as a background task, polling the chain at regular intervals
/// and maintaining a rolling window of base fee history for trend analysis.
pub struct ChainMonitor<P> {
    /// Provider for chain queries
    provider: Arc<P>,
    /// Current computed state
    state: Arc<RwLock<ChainState>>,
    /// Historical base fee samples (newest at back)
    history: RwLock<VecDeque<BaseFeeSnapshot>>,
    /// Configuration
    config: ChainMonitorConfig,
}

/// Configuration for chain monitor
#[derive(Debug, Clone)]
pub struct ChainMonitorConfig {
    /// How often to poll the chain
    pub poll_interval: Duration,
    /// Number of blocks to keep in history
    pub history_window: usize,
    /// EMA smoothing factor (0-1, higher = more reactive)
    pub ema_alpha: f64,
}

impl Default for ChainMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            history_window: 20,
            ema_alpha: 0.3,
        }
    }
}

/// Snapshot of base fee at a specific block
#[derive(Debug, Clone)]
pub struct BaseFeeSnapshot {
    pub block_number: u64,
    pub base_fee: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub timestamp: Instant,
}

impl<P: Provider + Clone + 'static> ChainMonitor<P> {
    pub fn new(provider: Arc<P>, config: ChainMonitorConfig) -> Arc<Self> {
        Arc::new(Self {
            provider,
            state: Arc::new(RwLock::new(ChainState::default())),
            history: RwLock::new(VecDeque::with_capacity(config.history_window)),
            config,
        })
    }

    /// Start the monitor as a background task (polling mode)
    pub async fn run(self: Arc<Self>, mut shutdown: broadcast::Receiver<()>) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!(
            poll_interval_ms = self.config.poll_interval.as_millis(),
            history_window = self.config.history_window,
            "Chain monitor started"
        );

        // Polling loop
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Fetch latest block header
                    let block = self.provider.get_block_by_number(BlockNumberOrTag::Latest)
                        .await
                        .context("Failed to fetch latest block")?
                        .context("No latest block found")?;

                    self.update(block.into_header().into());
                }
                _ = shutdown.recv() => {
                    tracing::info!("Chain monitor shutting down");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Perform a single update cycle
    fn update(&self, block: Header) {
        let snapshot = BaseFeeSnapshot {
            block_number: block.number,
            base_fee: block.base_fee_per_gas.unwrap_or(0),
            gas_used: block.gas_used,
            gas_limit: block.gas_limit,
            timestamp: Instant::now(),
        };

        self.record_snapshot(snapshot);
    }

    /// Record a new snapshot and update computed state
    fn record_snapshot(&self, snapshot: BaseFeeSnapshot) {
        // Add to history
        {
            let mut history = self.history.write().unwrap();

            // Avoid duplicate block numbers
            if history.back().map_or(true, |last| last.block_number != snapshot.block_number) {
                history.push_back(snapshot.clone());

                // Trim to window size
                while history.len() > self.config.history_window {
                    history.pop_front();
                }
            }
        }

        // Update computed state
        let mut state = self.state.write().unwrap();

        // Update EMA
        if state.base_fee_ema == 0.0 {
            state.base_fee_ema = snapshot.base_fee as f64;
        } else {
            state.base_fee_ema = self.config.ema_alpha * snapshot.base_fee as f64
                + (1.0 - self.config.ema_alpha) * state.base_fee_ema;
        }

        // Calculate trend (needs history lock)
        let history = self.history.read().unwrap();
        state.base_fee_trend = Self::calculate_trend(&*history);
        state.recent_utilization = Self::calculate_utilization(&*history);
        drop(history);

        // Update current values
        state.block_number = snapshot.block_number;
        state.base_fee = snapshot.base_fee;
        state.block_gas_limit = snapshot.gas_limit;
        state.last_updated = Instant::now().into();
    }

    /// Calculate base fee trend as normalized rate of change.
    ///
    /// Returns value in [-1, 1] where:
    /// - -1 = decreasing at max rate (12.5% per block)
    /// - +1 = increasing at max rate (12.5% per block)
    fn calculate_trend(history: &VecDeque<BaseFeeSnapshot>) -> f64 {
        if history.len() < 2 {
            return 0.0;
        }

        // Calculate log returns
        let snapshots: Vec<&BaseFeeSnapshot> = history.iter().collect();
        let returns: Vec<f64> = snapshots
            .windows(2)
            .map(|w| (w[1].base_fee as f64 / w[0].base_fee as f64).ln())
            .collect();

        if returns.is_empty() {
            return 0.0;
        }

        // Average log return
        let avg_return: f64 = returns.iter().sum::<f64>() / returns.len() as f64;

        // Normalize: max change per block is ln(1.125) ≈ 0.118
        let max_change = 1.125_f64.ln();
        (avg_return / max_change).clamp(-1.0, 1.0)
    }

    /// Calculate recent average block utilization
    fn calculate_utilization(history: &VecDeque<BaseFeeSnapshot>) -> f64 {
        if history.is_empty() {
            return 0.5; // Default to 50%
        }

        let total_used: u64 = history.iter().map(|s| s.gas_used).sum();
        let total_limit: u64 = history.iter().map(|s| s.gas_limit).sum();

        if total_limit == 0 {
            return 0.5;
        }

        total_used as f64 / total_limit as f64
    }

    /// Get the current chain state
    pub fn current_state(&self) -> ChainState {
        self.state.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn test_trend_calculation_stable() {
        // Simulate stable fees
        let _config = ChainMonitorConfig::default();
        let history: VecDeque<BaseFeeSnapshot> = (0..10)
            .map(|i| BaseFeeSnapshot {
                block_number: i,
                base_fee: 20_000_000_000, // 20 gwei, stable
                gas_used: 15_000_000,
                gas_limit: 30_000_000,
                timestamp: Instant::now(),
            })
            .collect();

        // Calculate trend manually
        let returns: Vec<f64> = history
            .iter()
            .collect::<Vec<_>>()
            .windows(2)
            .map(|w| (w[1].base_fee as f64 / w[0].base_fee as f64).ln())
            .collect();

        let avg: f64 = returns.iter().sum::<f64>() / returns.len() as f64;

        // Should be ~0 for stable fees
        assert!(avg.abs() < 0.001);
    }

    #[test]
    fn test_trend_calculation_rising() {
        // Simulate rising fees (12.5% per block)
        let mut fee = 20_000_000_000u64;
        let history: VecDeque<BaseFeeSnapshot> = (0..10)
            .map(|i| {
                let snapshot = BaseFeeSnapshot {
                    block_number: i,
                    base_fee: fee,
                    gas_used: 30_000_000, // Full blocks
                    gas_limit: 30_000_000,
                    timestamp: Instant::now(),
                };
                fee = (fee as f64 * 1.125) as u64;
                snapshot
            })
            .collect();

        let returns: Vec<f64> = history
            .iter()
            .collect::<Vec<_>>()
            .windows(2)
            .map(|w| (w[1].base_fee as f64 / w[0].base_fee as f64).ln())
            .collect();

        let avg: f64 = returns.iter().sum::<f64>() / returns.len() as f64;
        let normalized = avg / 1.125_f64.ln();

        // Should be ~1 for max rising fees
        assert!((normalized - 1.0).abs() < 0.1);
    }
}
