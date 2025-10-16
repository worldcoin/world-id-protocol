use std::net::SocketAddr;

use alloy::{network::EthereumWallet, primitives::Address, signers::local::PrivateKeySigner};

#[derive(Clone, Debug)]
pub struct GatewayConfig {
    /// The address of the `AccountRegistry` contract
    pub registry_addr: Address,
    /// The HTTP RPC endpoint to submit transactions
    pub rpc_url: String,
    /// The signer wallet that will submit transactions (pays for gas)
    pub ethereum_wallet: EthereumWallet,
    /// Batch window in milliseconds (i.e. how long to wait before submitting a batch of transactions)
    pub batch_ms: u64,
    /// The address and port to listen for HTTP requests
    pub listen_addr: SocketAddr,
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        let listen_addr: SocketAddr = std::env::var("RG_HTTP_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8081".to_string())
            .parse()
            .unwrap();

        if listen_addr.port() != 8080 {
            tracing::warn!("Indexer is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)");
        }

        let wallet_sk =
            std::env::var("WALLET_PRIVATE_KEY").expect("WALLET_PRIVATE_KEY (hex) is required");
        let ethereum_wallet = EthereumWallet::from(wallet_sk.parse::<PrivateKeySigner>().unwrap());

        Self {
            registry_addr: std::env::var("REGISTRY_ADDRESS")
                .expect("REGISTRY_ADDRESS is required")
                .parse()
                .expect("invalid REGISTRY_ADDRESS"),
            rpc_url: std::env::var("RPC_URL").expect("RPC_URL is required"),
            ethereum_wallet,
            batch_ms: std::env::var("RG_BATCH_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            listen_addr,
        }
    }
}
