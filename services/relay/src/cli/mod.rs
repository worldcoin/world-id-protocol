use clap::Args;
use serde::Deserialize;

use std::{path::PathBuf, str::FromStr, sync::Arc};

use alloy_primitives::Address;
use world_id_services_common::ProviderArgs;

use crate::{engine::Engine, satellite::EthereumMptSatellite};

pub mod chain;
pub use chain::WorldChain;

/// World ID Bridge Relay Service.
#[derive(clap::Parser, Debug, Deserialize)]
#[command(
    name = "world-id-relay",
    version,
    about = "World ID Bridge Relay Service"
)]
pub struct Cli {
    #[command(flatten)]
    pub world_chain: WorldChainConfig,

    #[command(flatten)]
    pub ethereum_chain: EthereumChainConfig,

    /// A List of satellite chains to relay to, specified as JSON strings
    #[arg(long, value_delimiter = ',', env = "SATELLITE_CHAINS")]
    #[serde(default)]
    pub satellite_chains: Vec<ChainConfig>,

    /// Optional path to a file containing the private key for signing messages.
    #[arg(long, env = "PRIVATE_KEY_FILE")]
    pub private_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Deserialize)]
pub struct WorldChainConfig {
    /// Chain ID of the Source Chain
    #[arg(long, env = "SOURCE_CHAIN_ID", default_value = "480")]
    pub chain_id: u64,
    /// WorldIDSource proxy address on World Chain.
    #[arg(long, env = "WC_SOURCE_ADDRESS")]
    pub world_id_source: Address,

    /// OPRF key registry address on World Chain.
    #[arg(long, env = "OPRF_KEY_REGISTRY")]
    pub oprf_key_registry: Address,

    /// Credential issuer schema registry address on World Chain.
    #[arg(long, env = "ISSUER_SCHEMA_REGISTRY")]
    pub credential_issuer_schema_registry: Address,

    /// World ID registry address on World Chain.
    #[arg(long, env = "WORLD_ID_REGISTRY")]
    pub world_id_registry: Address,

    #[command(flatten)]
    pub provider: ProviderArgs,

    /// Batch interval in seconds for periodic propagateState calls.
    #[arg(long, env = "BRIDGE_INTERVAL_SECS", default_value = "3600")]
    pub bridge_interval: u64,
}

#[derive(Debug, Clone, Args, Deserialize)]
#[command(next_help_heading = "Ethereum Chain Configuration")]
pub struct EthereumChainConfig {
    #[command(flatten)]
    pub base: ChainConfig,

    /// The dispute game factory contract on this chain.
    #[arg(long, env = "DISPUTE_GAME_FACTORY")]
    pub dispute_game_factory: Address,

    /// The dispute game type for this chain (default: 0 = CANNON).
    #[arg(long, env = "GAME_TYPE", default_value_t = 0)]
    #[serde(default)]
    pub game_type: u32,

    /// Whether to require dispute games to be finalized (DEFENDER_WINS) before relaying.
    #[arg(long, env = "REQUIRE_FINALIZED", default_value_t = false)]
    #[serde(default)]
    pub require_finalized: bool,
}

#[derive(Debug, Clone, Args, Deserialize)]
pub struct ChainConfig {
    #[command(flatten)]
    pub provider: ProviderArgs,

    /// The bridge contract on this chain.
    #[arg(long, env = "SATELLITE_BRIDGE_ADDRESS")]
    pub satellite: Address,

    /// The gateway contract on this chain.
    #[arg(long, env = "SATELLITE_GATEWAY_ADDRESS")]
    pub gateway: Address,

    // /// The chain ID for this chain.
    #[arg(long, env = "SATELLITE_CHAIN_ID", default_value = "1")]
    pub chain_id: u64,
}

impl FromStr for ChainConfig {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map_err(|e| eyre::eyre!("failed to parse ChainConfig from JSON: {e}"))
    }
}

impl Cli {
    pub async fn run(self) -> eyre::Result<()> {
        let shutdown = tokio::signal::ctrl_c();

        // Build providers once at the top level, then share via Arc.
        let wc_provider = Arc::new(self.world_chain.provider.clone().http().await?);
        let eth_provider = Arc::new(self.ethereum_chain.base.provider.clone().http().await?);

        let world_chain = chain::WorldChain::new(&self.world_chain, wc_provider.clone());

        let ethereum = EthereumMptSatellite::from_config(
            &self.world_chain,
            &self.ethereum_chain,
            wc_provider,
            eth_provider,
        );

        let mut engine = Engine::new(world_chain);
        engine.spawn_satellite(ethereum);

        tokio::select! {
            result = engine.run() => result,
            _ = shutdown => {
                tracing::info!("received shutdown signal");
                Ok(())
            }
        }
    }
}
