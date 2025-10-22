use std::net::SocketAddr;

use alloy::{network::EthereumWallet, primitives::Address, signers::local::PrivateKeySigner};
use clap::Parser;

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
    #[arg(long, env = "WALLET_PRIVATE_KEY", value_parser = parse_wallet)]
    pub ethereum_wallet: EthereumWallet,

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
}

fn parse_wallet(s: &str) -> Result<EthereumWallet, String> {
    let signer = s
        .parse::<PrivateKeySigner>()
        .map_err(|e| format!("invalid private key: {}", e))?;
    Ok(EthereumWallet::from(signer))
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        let config = Self::parse();

        if config.listen_addr.port() != 8080 {
            tracing::warn!("Gateway is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)");
        }

        config
    }
}
