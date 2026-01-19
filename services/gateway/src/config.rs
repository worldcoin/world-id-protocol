use std::net::SocketAddr;

use alloy::primitives::Address;
use clap::Parser;
use common::ProviderArgs;

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

    /// Metrics configuration
    #[command(flatten)]
    pub metrics: MetricsArgs,
}

/// Metrics and observability configuration.
#[derive(Clone, Debug, clap::Args)]
#[command(next_help_heading = "Metrics")]
#[group(id = "metrics", multiple = true, requires = "enabled")]
pub struct MetricsArgs {
    /// Enable metrics collection
    #[arg(long = "metrics", env = "METRICS_ENABLED", default_value = "false")]
    pub enabled: bool,

    /// Optional address for Prometheus metrics endpoint (e.g. 0.0.0.0:9090)
    /// If not provided, Prometheus metrics endpoint is disabled
    #[arg(long = "metrics.addr", env = "METRICS_ADDR", group = "metrics")]
    pub addr: Option<SocketAddr>,

    /// Optional OTLP endpoint for metrics export (e.g. http://localhost:4317)
    /// If not provided, OTLP export is disabled
    #[arg(long = "otlp.endpoint", env = "OTLP_ENDPOINT", group = "metrics")]
    pub otlp_endpoint: Option<String>,

    /// Service name for metrics reporting
    #[arg(
        long = "otlp.service-name",
        env = "SERVICE_NAME",
        default_value = "world-id-gateway",
        group = "metrics"
    )]
    pub service_name: String,
}

impl Default for MetricsArgs {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: None,
            otlp_endpoint: None,
            service_name: "world-id-gateway".to_string(),
        }
    }
}

impl MetricsArgs {
    /// Returns true if metrics collection is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        Self::parse()
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

    #[test]
    fn test_metrics_disabled_by_default() {
        let result = parse_with_signer_args(&["--wallet-private-key", "0xdeadbeef"]);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(!config.metrics.is_enabled());
        assert!(config.metrics.addr.is_none());
        assert!(config.metrics.otlp_endpoint.is_none());
    }

    #[test]
    fn test_metrics_enabled() {
        let result = parse_with_signer_args(&["--wallet-private-key", "0xdeadbeef", "--metrics"]);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(config.metrics.is_enabled());
    }

    #[test]
    fn test_metrics_with_addr() {
        let result = parse_with_signer_args(&[
            "--wallet-private-key",
            "0xdeadbeef",
            "--metrics",
            "--metrics.addr",
            "0.0.0.0:9090",
        ]);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(config.metrics.is_enabled());
        assert_eq!(config.metrics.addr, Some("0.0.0.0:9090".parse().unwrap()));
    }

    #[test]
    fn test_metrics_with_otlp() {
        let result = parse_with_signer_args(&[
            "--wallet-private-key",
            "0xdeadbeef",
            "--metrics",
            "--otlp.endpoint",
            "http://localhost:4317",
        ]);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(config.metrics.is_enabled());
        assert_eq!(
            config.metrics.otlp_endpoint,
            Some("http://localhost:4317".to_string())
        );
    }

    #[test]
    fn test_metrics_addr_requires_metrics_flag() {
        let result = parse_with_signer_args(&[
            "--wallet-private-key",
            "0xdeadbeef",
            "--metrics.addr",
            "0.0.0.0:9090",
        ]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn test_metrics_otlp_requires_metrics_flag() {
        let result = parse_with_signer_args(&[
            "--wallet-private-key",
            "0xdeadbeef",
            "--otlp.endpoint",
            "http://localhost:4317",
        ]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }
}
