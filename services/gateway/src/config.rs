use std::net::SocketAddr;

use alloy::primitives::Address;
use clap::Parser;

#[derive(Clone, Debug)]
pub enum SignerConfig {
    PrivateKey(String),
    AwsKms(String),
}

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct GatewayConfig {
    /// The address of the `AccountRegistry` contract
    #[arg(long, env = "REGISTRY_ADDRESS")]
    pub registry_addr: Address,

    /// The HTTP RPC endpoint to submit transactions
    #[arg(long, env = "RPC_URL")]
    pub rpc_url: String,

    /// The signer wallet private key (hex) that will submit transactions (pays for gas)
    /// Mutually exclusive with AWS_KMS_KEY_ID
    #[arg(long, env = "WALLET_PRIVATE_KEY")]
    pub wallet_private_key: Option<String>,

    /// AWS KMS Key ID for signing transactions
    /// Mutually exclusive with WALLET_PRIVATE_KEY
    #[arg(long, env = "AWS_KMS_KEY_ID")]
    pub aws_kms_key_id: Option<String>,

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
            tracing::warn!("Gateway is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)");
        }

        config
    }

    pub fn signer_config(&self) -> anyhow::Result<SignerConfig> {
        match (&self.wallet_private_key, &self.aws_kms_key_id) {
            (Some(pk), None) => Ok(SignerConfig::PrivateKey(pk.clone())),
            (None, Some(key_id)) => Ok(SignerConfig::AwsKms(key_id.clone())),
            (Some(_), Some(_)) => Err(anyhow::anyhow!(
                "Cannot specify both WALLET_PRIVATE_KEY and AWS_KMS_KEY_ID"
            )),
            (None, None) => Err(anyhow::anyhow!(
                "Must specify either WALLET_PRIVATE_KEY or AWS_KMS_KEY_ID"
            )),
        }
    }
}
