use std::net::SocketAddr;

use alloy::primitives::Address;
use clap::Parser;
use world_id_services_common::ProviderArgs;

use crate::error::{GatewayError, GatewayResult};

/// Rate limiting configuration for leaf_index-based requests.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub window_secs: u64,
    pub max_requests: u64,
}

/// Configuration for the orphan sweeper background task.
#[derive(Clone, Debug, clap::Args)]
pub struct OrphanSweeperConfig {
    /// How often the orphan sweeper runs, in seconds.
    #[arg(long, env = "ORPHAN_SWEEPER_INTERVAL_SECS", default_value = "30")]
    pub interval_secs: u64,

    /// Staleness threshold for Queued/Batching requests (seconds).
    #[arg(long, env = "STALE_QUEUED_THRESHOLD_SECS", default_value = "60")]
    pub stale_queued_threshold_secs: u64,

    /// Staleness threshold for Submitted requests with no receipt (seconds).
    #[arg(long, env = "STALE_SUBMITTED_THRESHOLD_SECS", default_value = "600")]
    pub stale_submitted_threshold_secs: u64,
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

    /// Batch window in milliseconds (i.e. how long to wait before submitting a batch of transactions)
    #[arg(long, env = "BATCH_MS", default_value = "1000")]
    pub batch_ms: u64,

    /// Maximum batch size for create account requests
    #[arg(long, env = "MAX_CREATE_BATCH_SIZE", default_value = "100")]
    pub max_create_batch_size: usize,

    /// Maximum batch size for ops (insert/update/remove/recover) requests
    #[arg(long, env = "MAX_OPS_BATCH_SIZE", default_value = "10")]
    pub max_ops_batch_size: usize,

    /// HTTP request timeout in seconds
    #[arg(long, env = "REQUEST_TIMEOUT_SECS", default_value = "10")]
    pub request_timeout_secs: u64,

    /// The address and port to listen for HTTP requests
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8081")]
    pub listen_addr: SocketAddr,

    /// Redis URL for request storage (e.g. redis://localhost:6379)
    #[arg(long, env = "REDIS_URL")]
    pub redis_url: String,

    /// Rate limit window in seconds for leaf_index-based requests (sliding window).
    /// Both this and --rate-limit-max-requests must be provided to enable rate limiting.
    #[arg(
        long,
        env = "RATE_LIMIT_WINDOW_SECS",
        requires = "rate_limit_max_requests"
    )]
    pub rate_limit_window_secs: Option<u64>,

    /// Maximum number of requests per leaf_index within the rate limit window.
    /// Both this and --rate-limit-window-secs must be provided to enable rate limiting.
    #[arg(
        long,
        env = "RATE_LIMIT_MAX_REQUESTS",
        requires = "rate_limit_window_secs"
    )]
    pub rate_limit_max_requests: Option<u64>,

    #[command(flatten)]
    pub sweeper: OrphanSweeperConfig,
}

impl GatewayConfig {
    /// Returns the rate limit configuration if both parameters are provided.
    pub fn rate_limit(&self) -> Option<RateLimitConfig> {
        match (self.rate_limit_window_secs, self.rate_limit_max_requests) {
            (Some(window_secs), Some(max_requests)) => Some(RateLimitConfig {
                window_secs,
                max_requests,
            }),
            _ => None,
        }
    }
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

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
}
