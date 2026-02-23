use clap::Args;
use serde::Deserialize;

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use alloy_primitives::Address;
use url::Url;
use world_id_services_common::ProviderArgs;

/// World ID Bridge Relay Service.
#[derive(clap::Parser, Debug, Deserialize)]
#[command(name = "world-id-relay", version, about)]
pub struct WorldIDRelayConfig {
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

    /// Optional URL of the monitoring service to send metrics to.
    #[arg(long, env = "MONITORING_URL")]
    pub monitoring_url: Option<Url>,
}

impl<P: AsRef<Path>> TryFrom<Option<P>> for WorldIDRelayConfig {
    type Error = eyre::Error;

    fn try_from(path: Option<P>) -> Result<Self, Self::Error> {
        dotenvy::dotenv().ok();

        let mut settings = config::Config::builder();

        if let Some(path) = path {
            settings = settings.add_source(config::File::from(path.as_ref()).required(true));
        }

        let settings = settings
            .add_source(
                config::Environment::default()
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        let config = settings.try_deserialize::<Self>()?;

        Ok(config)
    }
}

#[derive(Debug, Clone, Args, Deserialize)]
pub struct WorldChainConfig {
    /// WorldIDSource proxy address on World Chain.
    #[arg(long, env = "WC_SOURCE_ADDRESS")]
    pub bridge: Address,

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
    #[arg(long, env = "BRIDGE_ADDRESS")]
    pub bridge: Address,

    /// The gateway contract on this chain.
    #[arg(long, env = "GATEWAY_ADDRESS")]
    pub gateway: Address,
}

impl FromStr for ChainConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map_err(|err| format!("Failed to parse ChainConfig from JSON: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn parse_full_config_from_toml() {
        let toml = r#"
private_key_file = "/tmp/key.hex"
monitoring_url = "https://monitor.example.com"

[world_chain]
bridge = "0x1111111111111111111111111111111111111111"
oprf_key_registry = "0x2222222222222222222222222222222222222222"
credential_issuer_schema_registry = "0x3333333333333333333333333333333333333333"
world_id_registry = "0x4444444444444444444444444444444444444444"

[world_chain.provider]
http = ["http://localhost:8545"]

[ethereum_chain]
dispute_game_factory = "0x6666666666666666666666666666666666666666"
game_type = 1
require_finalized = true

[ethereum_chain.base]
bridge = "0x7777777777777777777777777777777777777777"
gateway = "0x8888888888888888888888888888888888888888"

[ethereum_chain.base.provider]
http = ["http://localhost:8546"]

[[satellite_chains]]
bridge = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
gateway = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

[satellite_chains.provider]
http = ["http://localhost:8547"]
"#;

        let dir = std::env::temp_dir();
        let path = dir.join("world_id_relay_test_full.toml");
        std::fs::write(&path, toml).unwrap();
        let config = WorldIDRelayConfig::try_from(Some(&path)).unwrap();
        std::fs::remove_file(&path).ok();

        // World Chain
        assert_eq!(
            config.world_chain.bridge,
            address!("1111111111111111111111111111111111111111")
        );
        assert_eq!(
            config.world_chain.oprf_key_registry,
            address!("2222222222222222222222222222222222222222")
        );
        assert_eq!(
            config.world_chain.credential_issuer_schema_registry,
            address!("3333333333333333333333333333333333333333")
        );
        assert_eq!(
            config.world_chain.world_id_registry,
            address!("4444444444444444444444444444444444444444")
        );

        // Ethereum chain
        assert_eq!(
            config.ethereum_chain.dispute_game_factory,
            address!("6666666666666666666666666666666666666666")
        );
        assert_eq!(config.ethereum_chain.game_type, 1);
        assert!(config.ethereum_chain.require_finalized);
        assert_eq!(
            config.ethereum_chain.base.bridge,
            address!("7777777777777777777777777777777777777777")
        );
        assert_eq!(
            config.ethereum_chain.base.gateway,
            address!("8888888888888888888888888888888888888888")
        );

        // Satellite chains
        assert_eq!(config.satellite_chains.len(), 1);
        assert_eq!(
            config.satellite_chains[0].bridge,
            address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(
            config.satellite_chains[0].gateway,
            address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        );

        // Optional fields
        assert_eq!(
            config.private_key_file.unwrap().to_str().unwrap(),
            "/tmp/key.hex"
        );
        assert_eq!(
            config.monitoring_url.unwrap().as_str(),
            "https://monitor.example.com/"
        );
    }

    #[test]
    fn parse_minimal_config_from_toml() {
        let toml = r#"
[world_chain]
bridge = "0x1111111111111111111111111111111111111111"
oprf_key_registry = "0x2222222222222222222222222222222222222222"
credential_issuer_schema_registry = "0x3333333333333333333333333333333333333333"
world_id_registry = "0x4444444444444444444444444444444444444444"

[world_chain.provider]
http = ["http://localhost:8545"]

[ethereum_chain]
dispute_game_factory = "0x6666666666666666666666666666666666666666"

[ethereum_chain.base]
bridge = "0x7777777777777777777777777777777777777777"
gateway = "0x8888888888888888888888888888888888888888"

[ethereum_chain.base.provider]
http = ["http://localhost:8546"]
"#;

        let dir = std::env::temp_dir();
        let path = dir.join("world_id_relay_test_minimal.toml");
        std::fs::write(&path, toml).unwrap();
        let config = WorldIDRelayConfig::try_from(Some(&path)).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(
            config.world_chain.bridge,
            address!("1111111111111111111111111111111111111111")
        );
        assert_eq!(config.ethereum_chain.game_type, 0);
        assert!(!config.ethereum_chain.require_finalized);
        assert!(config.satellite_chains.is_empty());
        assert!(config.private_key_file.is_none());
        assert!(config.monitoring_url.is_none());
    }
}
