use std::{net::SocketAddr, time::Duration};

use alloy::primitives::Address;
use clap::Parser;
use common::ProviderArgs;
use serde::Deserialize;

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

    /// The address and port to listen for HTTP requests
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8081")]
    pub listen_addr: SocketAddr,

    /// Optional Redis URL for multi-pod request storage (e.g. redis://localhost:6379)
    /// If not provided, requests will be stored in-memory
    #[arg(long, env = "REDIS_URL")]
    pub redis_url: Option<String>,
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        let config = Self::parse();

        if config.listen_addr.port() != 8080 {
            tracing::warn!(
                "Gateway is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)"
            );
        }

        config
    }
}

#[derive(Debug, Clone, clap::Args, Default, Deserialize)]

pub struct PendingBatchConfig {
    #[clap(long, env = "RESUBMIT_TIMEOUT", default_value = "15s", value_parser = parser::parse_duration)]
    pub resubmit_timeout: Duration,
    #[clap(long, env = "MAX_FEE_MULTIPLIER", default_value = "2.0")]
    pub max_fee_multiplier: f64,
    #[clap(long, env = "FEE_ESCALATION_STEP", default_value = "0.1")]
    pub fee_escalation_step: f64,
    #[clap(long, env = "MAX_RESUBMISSIONS", default_value = "5")]
    pub max_resubmissions: u32,
    #[clap(long, env = "SIMULATION_TIMEOUT", default_value = "10s", value_parser = parser::parse_duration)]
    pub simulation_timeout: Duration,
    #[clap(long, env = "SIMULATION_DEBOUNCE", default_value = "500ms", value_parser = parser::parse_duration)]
    pub simulation_debounce: Duration,
    #[clap(long, env = "MAX_PENDING_DURATION", default_value = "5m", value_parser = parser::parse_duration)]
    pub max_pending_duration: Duration,
    #[clap(long, env = "RETRY_BASE_DELAY", default_value = "500ms", value_parser = parser::parse_duration)]
    pub retry_base_delay: Duration,
}

mod parser {
    use std::time::Duration;

    pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
        Ok(Duration::from_secs(Duration::from_secs(s.parse::<u64>()?).as_secs()))
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
    fn test_neither_option_fails() {
        let result = parse_with_signer_args(&[]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }
}
