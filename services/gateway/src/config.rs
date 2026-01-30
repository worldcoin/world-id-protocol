use std::net::SocketAddr;

use alloy::primitives::Address;
use clap::Parser;
use world_id_common::ProviderArgs;

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
