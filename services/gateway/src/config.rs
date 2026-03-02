use std::net::SocketAddr;

use alloy::primitives::Address;
use clap::Parser;
use world_id_services_common::ProviderArgs;

use crate::error::{GatewayError, GatewayResult};

pub mod defaults {
    pub const MAX_CREATE_BATCH_SIZE: usize = 100;
    pub const MAX_OPS_BATCH_SIZE: usize = 10;
    pub const REQUEST_TIMEOUT_SECS: u64 = 10;
    pub const LISTEN_ADDR: &str = "0.0.0.0:8081";
    pub const SWEEPER_INTERVAL_SECS: u64 = 30;
    pub const STALE_QUEUED_THRESHOLD_SECS: u64 = 60;
    pub const STALE_SUBMITTED_THRESHOLD_SECS: u64 = 600;
}

/// Batching configuration for transaction submission.
#[derive(Clone, Debug)]
pub struct BatcherConfig {
    pub max_create_batch_size: usize,
    pub max_ops_batch_size: usize,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            max_create_batch_size: defaults::MAX_CREATE_BATCH_SIZE,
            max_ops_batch_size: defaults::MAX_OPS_BATCH_SIZE,
        }
    }
}

/// Rate limiting configuration for leaf_index-based requests.
///
/// Both fields are always present — the optionality is expressed at the
/// call-site via `Option<RateLimitConfig>`.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub window_secs: u64,
    pub max_requests: u64,
}

/// Configuration for the orphan sweeper background task.
#[derive(Clone, Debug)]
pub struct OrphanSweeperConfig {
    pub interval_secs: u64,
    pub stale_queued_threshold_secs: u64,
    pub stale_submitted_threshold_secs: u64,
}

impl Default for OrphanSweeperConfig {
    fn default() -> Self {
        Self {
            interval_secs: defaults::SWEEPER_INTERVAL_SECS,
            stale_queued_threshold_secs: defaults::STALE_QUEUED_THRESHOLD_SECS,
            stale_submitted_threshold_secs: defaults::STALE_SUBMITTED_THRESHOLD_SECS,
        }
    }
}

/// Policy-driven batching configuration.
#[derive(Clone, Debug, clap::Args)]
pub struct BatchPolicyConfig {
    /// Re-evaluation cadence for policy decisions, in milliseconds.
    #[arg(long, env = "BATCH_REEVAL_MS", default_value = "1000")]
    pub reeval_ms: u64,

    /// Hard max wait for queued requests before forcing send, in seconds.
    #[arg(long, env = "BATCH_MAX_WAIT_SECS", default_value = "30")]
    pub max_wait_secs: u64,

    /// EMA alpha for base fee smoothing in [0, 1].
    #[arg(long, env = "BATCH_COST_EMA_ALPHA", default_value = "0.2")]
    pub cost_ema_alpha: f64,

    /// Cost pressure threshold: cost_score >= threshold is considered expensive.
    #[arg(long, env = "BATCH_COST_HIGH_RATIO", default_value = "1.2")]
    pub cost_high_ratio: f64,

    /// Backlog size where urgency size pressure reaches 1.0.
    #[arg(long, env = "BATCH_BACKLOG_HIGH_WATERMARK", default_value = "200")]
    pub backlog_high_watermark: usize,
}

impl Default for BatchPolicyConfig {
    fn default() -> Self {
        Self {
            reeval_ms: 1_000,
            max_wait_secs: 30,
            cost_ema_alpha: 0.2,
            cost_high_ratio: 1.2,
            backlog_high_watermark: 200,
        }
    }
}

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct GatewayConfig {
    /// The address of the `WorldIDRegistry` contract
    #[arg(long, env = "REGISTRY_ADDRESS")]
    pub registry_addr: Address,

    /// The HTTP RPC endpoint to submit transactions
    #[command(flatten)]
    pub provider: ProviderArgs,

    /// Maximum batch size for create account requests
    #[arg(long, env = "MAX_CREATE_BATCH_SIZE", default_value_t = defaults::MAX_CREATE_BATCH_SIZE)]
    pub max_create_batch_size: usize,

    /// Maximum batch size for ops (insert/update/remove/recover) requests
    #[arg(long, env = "MAX_OPS_BATCH_SIZE", default_value_t = defaults::MAX_OPS_BATCH_SIZE)]
    pub max_ops_batch_size: usize,

    /// HTTP request timeout in seconds
    #[arg(long, env = "REQUEST_TIMEOUT_SECS", default_value_t = defaults::REQUEST_TIMEOUT_SECS)]
    pub request_timeout_secs: u64,

    /// The address and port to listen for HTTP requests
    #[arg(long, env = "LISTEN_ADDR", default_value = defaults::LISTEN_ADDR)]
    pub listen_addr: SocketAddr,

    /// Redis URL for request storage (e.g. redis://localhost:6379)
    #[arg(long, env = "REDIS_URL")]
    pub redis_url: String,

    /// Rate limit window in seconds (sliding window). Requires --rate-limit-max-requests.
    #[arg(
        long = "rate-limit-window-secs",
        env = "RATE_LIMIT_WINDOW_SECS",
        requires = "rate_limit_max_requests"
    )]
    pub rate_limit_window_secs: Option<u64>,

    /// Maximum requests per leaf_index within the rate limit window. Requires --rate-limit-window-secs.
    #[arg(
        long = "rate-limit-max-requests",
        env = "RATE_LIMIT_MAX_REQUESTS",
        requires = "rate_limit_window_secs"
    )]
    pub rate_limit_max_requests: Option<u64>,

    /// How often the orphan sweeper runs, in seconds.
    #[arg(long, env = "ORPHAN_SWEEPER_INTERVAL_SECS", default_value_t = defaults::SWEEPER_INTERVAL_SECS)]
    pub sweeper_interval_secs: u64,

    #[command(flatten)]
    pub batch_policy: BatchPolicyConfig,

    /// Staleness threshold for Queued/Batching requests (seconds).
    #[arg(long, env = "STALE_QUEUED_THRESHOLD_SECS", default_value_t = defaults::STALE_QUEUED_THRESHOLD_SECS)]
    pub stale_queued_threshold_secs: u64,

    /// Staleness threshold for Submitted requests with no receipt (seconds).
    #[arg(long, env = "STALE_SUBMITTED_THRESHOLD_SECS", default_value_t = defaults::STALE_SUBMITTED_THRESHOLD_SECS)]
    pub stale_submitted_threshold_secs: u64,
}

impl GatewayConfig {
    pub fn from_env() -> GatewayResult<Self> {
        let config = Self::parse();
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> GatewayResult<()> {
        if self.provider.signer.is_none() {
            return Err(GatewayError::Config(
                "exactly one of --wallet-private-key or --aws-kms-key-id must be provided"
                    .to_string(),
            ));
        }

        if self.listen_addr.port() != 8080 {
            tracing::warn!(
                "Gateway is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)"
            );
        }

        if !(0.0..=1.0).contains(&self.batch_policy.cost_ema_alpha) {
            return Err(GatewayError::Config(
                "BATCH_COST_EMA_ALPHA must be in the inclusive range [0, 1]".to_string(),
            ));
        }

        if self.batch_policy.reeval_ms == 0 {
            return Err(GatewayError::Config(
                "BATCH_REEVAL_MS must be greater than 0".to_string(),
            ));
        }

        if self.batch_policy.max_wait_secs == 0 {
            return Err(GatewayError::Config(
                "BATCH_MAX_WAIT_SECS must be greater than 0".to_string(),
            ));
        }

        let max_wait_ms = (self.batch_policy.max_wait_secs as u128) * 1000;
        if (self.batch_policy.reeval_ms as u128) > max_wait_ms {
            return Err(GatewayError::Config(
                "BATCH_REEVAL_MS must be less than or equal to BATCH_MAX_WAIT_SECS * 1000"
                    .to_string(),
            ));
        }

        if !self.batch_policy.cost_high_ratio.is_finite() {
            return Err(GatewayError::Config(
                "BATCH_COST_HIGH_RATIO must be a finite number".to_string(),
            ));
        }

        if self.batch_policy.cost_high_ratio <= 0.0 {
            return Err(GatewayError::Config(
                "BATCH_COST_HIGH_RATIO must be greater than 0".to_string(),
            ));
        }

        if self.batch_policy.backlog_high_watermark == 0 {
            return Err(GatewayError::Config(
                "BATCH_BACKLOG_HIGH_WATERMARK must be greater than 0".to_string(),
            ));
        }

        if self.sweeper().stale_queued_threshold_secs <= self.batch_policy.max_wait_secs {
            return Err(GatewayError::Config(
                "STALE_QUEUED_THRESHOLD_SECS must be greater than BATCH_MAX_WAIT_SECS".to_string(),
            ));
        }

        Ok(())
    }

    pub fn batcher(&self) -> BatcherConfig {
        BatcherConfig {
            max_create_batch_size: self.max_create_batch_size,
            max_ops_batch_size: self.max_ops_batch_size,
        }
    }

    pub fn rate_limit(&self) -> Option<RateLimitConfig> {
        match (self.rate_limit_window_secs, self.rate_limit_max_requests) {
            (Some(window_secs), Some(max_requests)) => Some(RateLimitConfig {
                window_secs,
                max_requests,
            }),
            _ => None,
        }
    }

    pub fn sweeper(&self) -> OrphanSweeperConfig {
        OrphanSweeperConfig {
            interval_secs: self.sweeper_interval_secs,
            stale_queued_threshold_secs: self.stale_queued_threshold_secs,
            stale_submitted_threshold_secs: self.stale_submitted_threshold_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    const BASE_ARGS: &[&str] = &[
        "test",
        "--registry-addr",
        "0x0000000000000000000000000000000000000001",
        "--rpc-url",
        "http://localhost:8545",
        "--redis-url",
        "redis://localhost:6379",
    ];

    fn parse_with_signer_args(signer_args: &[&str]) -> Result<GatewayConfig, clap::Error> {
        let args: Vec<&str> = BASE_ARGS
            .iter()
            .chain(signer_args.iter())
            .copied()
            .collect();
        GatewayConfig::try_parse_from(args)
    }

    fn parse_valid_config() -> GatewayConfig {
        parse_with_signer_args(&["--wallet-private-key", TEST_PRIVATE_KEY])
            .expect("valid config should parse")
    }

    #[test]
    fn test_both_options_fails() {
        let result = parse_with_signer_args(&[
            "--wallet-private-key",
            "0xdeadbeef",
            "--aws-kms-key-id",
            "my-key-id",
        ]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_neither_option_fails_validation() {
        let config = parse_with_signer_args(&[]).expect("clap parsing should succeed");
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("wallet-private-key"));
    }

    #[test]
    fn rate_limit_disabled_when_omitted() {
        let config = parse_with_signer_args(&[]).expect("clap parsing should succeed");
        assert!(config.rate_limit().is_none());
    }

    #[test]
    fn rate_limit_enabled_when_both_provided() {
        let config = parse_with_signer_args(&[
            "--rate-limit-window-secs",
            "60",
            "--rate-limit-max-requests",
            "100",
        ])
        .expect("clap parsing should succeed");
        let rl = config.rate_limit().expect("rate_limit should be Some");
        assert_eq!(rl.window_secs, 60);
        assert_eq!(rl.max_requests, 100);
    }

    #[test]
    fn rate_limit_rejects_only_window() {
        let result = parse_with_signer_args(&["--rate-limit-window-secs", "60"]);
        assert!(result.is_err(), "providing only window_secs should fail");
    }

    #[test]
    fn rate_limit_rejects_only_max_requests() {
        let result = parse_with_signer_args(&["--rate-limit-max-requests", "100"]);
        assert!(result.is_err(), "providing only max_requests should fail");
    }

    #[test]
    fn test_reeval_ms_must_not_exceed_max_wait_ms() {
        let mut config = parse_valid_config();
        config.batch_policy.max_wait_secs = 30;
        config.batch_policy.reeval_ms = 31_000;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("BATCH_REEVAL_MS"));
    }

    #[test]
    fn test_cost_high_ratio_must_be_finite() {
        let mut config = parse_valid_config();
        config.batch_policy.cost_high_ratio = f64::NAN;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("BATCH_COST_HIGH_RATIO"));
        assert!(err.contains("finite"));
    }

    #[test]
    fn test_stale_queued_threshold_must_exceed_max_wait_secs() {
        let mut config = parse_valid_config();
        config.batch_policy.max_wait_secs = 30;
        config.stale_queued_threshold_secs = 30;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("STALE_QUEUED_THRESHOLD_SECS"));
    }
}
