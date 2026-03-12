use std::{fmt, path::PathBuf, sync::Arc};

use regex::Regex;
use serde::Deserialize;

use alloy_primitives::Address;
use world_id_services_common::{ProviderArgs, SignerArgs};

use crate::{
    engine::Engine,
    satellite::{EthereumMptSatellite, PermissionedSatellite},
};

pub mod chain;
pub use chain::WorldChain;

/// World ID Bridge Relay Service.
#[derive(clap::Parser, Debug)]
#[command(
    name = "world-id-relay",
    version,
    about = "World ID Bridge Relay Service"
)]
pub struct Cli {
    /// Path to the relay config file (JSON).
    ///
    /// Contains the world chain source configuration and all satellite chain
    /// definitions in a single file. See [`RelayConfig`] for the full schema.
    ///
    /// Mutually exclusive with `--config-json` / `RELAY_CONFIG`.
    #[arg(long, env = "RELAY_CONFIG_FILE")]
    pub config: Option<PathBuf>,

    /// Inline relay config as a JSON string.
    ///
    /// Use this instead of `--config` when you want to pass the full config
    /// via an environment variable (e.g. in Kubernetes deployments).
    #[arg(long, env = "RELAY_CONFIG")]
    pub config_json: Option<String>,

    /// Optional path to a file containing the private key for signing messages.
    #[arg(long, env = "PRIVATE_KEY_FILE")]
    pub private_key_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Config file schema
// ---------------------------------------------------------------------------

/// Top-level relay configuration, loaded from a single JSON file.
///
/// ```json
/// {
///   "source": {
///     "chain_id": 480,
///     "rpc_url": "https://...",
///     "world_id_source": "0x...",
///     "world_id_registry": "0x...",
///     "oprf_key_registry": "0x...",
///     "issuer_schema_registry": "0x...",
///     "bridge_interval_secs": 3600
///   },
///   "satellite_chains": [
///     {
///       "name": "sepolia",
///       "type": "ethereum_mpt",
///       "chain_id": 11155111,
///       "rpc_url": "https://...",
///       "source_address": "0x...",
///       "gateway": "0x...",
///       "satellite": "0x...",
///       "dispute_game_factory": "0x...",
///       "game_type": 0,
///       "require_finalized": false
///     },
///     {
///       "name": "base_sepolia",
///       "type": "permissioned",
///       "chain_id": 84532,
///       "rpc_url": "https://...",
///       "source_address": "0x...",
///       "gateway": "0x...",
///       "satellite": "0x..."
///     }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    /// World Chain (source of truth) configuration.
    pub source: SourceConfig,

    /// Destination chains to relay state to.
    pub satellite_chains: Vec<SatelliteConfig>,
}

/// World Chain source configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SourceConfig {
    /// Chain ID of the source chain (default: 480 for World Chain).
    #[serde(default = "default_source_chain_id")]
    pub chain_id: u64,

    /// RPC endpoint for the source chain.
    pub rpc_url: String,

    /// WorldIDSource proxy address.
    pub world_id_source: Address,

    /// WorldIDRegistry address.
    pub world_id_registry: Address,

    /// OprfKeyRegistry address.
    pub oprf_key_registry: Address,

    /// CredentialIssuerSchemaRegistry address.
    pub issuer_schema_registry: Address,

    /// Interval in seconds between periodic `propagateState` calls.
    #[serde(default = "default_bridge_interval")]
    pub bridge_interval_secs: u64,
}

fn default_source_chain_id() -> u64 {
    480
}

fn default_bridge_interval() -> u64 {
    3600
}

/// Adapter type for a satellite chain.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterType {
    /// Owner-attested chain head (no proofs required).
    Permissioned,
    /// OP Stack dispute game + MPT storage proofs.
    EthereumMpt,
}

impl fmt::Display for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permissioned => write!(f, "permissioned"),
            Self::EthereumMpt => write!(f, "ethereum_mpt"),
        }
    }
}

/// Configuration for a single satellite (destination) chain.
///
/// Common fields are always required. The `type` field determines which
/// adapter is used and which additional fields are required.
#[derive(Debug, Clone, Deserialize)]
pub struct SatelliteConfig {
    /// Human-readable name for logging (e.g. "sepolia", "base_sepolia").
    pub name: String,

    /// The adapter type: `"permissioned"` or `"ethereum_mpt"`.
    #[serde(rename = "type")]
    pub adapter: AdapterType,

    /// The destination chain ID.
    pub chain_id: u64,

    /// RPC endpoint for the destination chain.
    pub rpc_url: String,

    /// WorldIDSource contract address on the source chain.
    pub source_address: Address,

    /// The ERC-7786 gateway address on the destination chain.
    pub gateway: Address,

    /// The WorldIDSatellite (bridge) proxy address on the destination chain.
    pub satellite: Address,

    // -- ethereum_mpt fields (required when type = "ethereum_mpt") --
    /// The DisputeGameFactory contract on the destination chain.
    #[serde(default)]
    pub dispute_game_factory: Option<Address>,

    /// The dispute game type (default: 0 = CANNON).
    #[serde(default)]
    pub game_type: u32,

    /// Whether to require dispute games to be finalized (DEFENDER_WINS).
    #[serde(default)]
    pub require_finalized: bool,
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/// Expands `${VAR_NAME}` references in a string with values from the environment.
fn expand_env_vars(input: &str) -> eyre::Result<String> {
    let re = Regex::new(r"\$\{([^}]+)\}").expect("valid regex");
    let mut result = input.to_string();
    for cap in re.captures_iter(input) {
        let var_name = &cap[1];
        let value = std::env::var(var_name).map_err(|_| {
            eyre::eyre!("relay config references ${{{}}} but it is not set", var_name)
        })?;
        result = result.replace(&cap[0], &value);
    }
    Ok(result)
}

/// Loads and validates the relay config from a JSON file or inline string.
///
/// String values in the JSON may contain `${ENV_VAR}` references which are
/// expanded from the process environment before parsing. This allows secrets
/// (e.g. RPC URLs) to be injected via environment variables while the rest of
/// the config remains plain text.
fn load_config(path: Option<&PathBuf>, inline: Option<&str>) -> eyre::Result<RelayConfig> {
    let raw = match (path, inline) {
        (Some(p), None) => std::fs::read_to_string(p)
            .map_err(|e| eyre::eyre!("failed to read config file `{}`: {e}", p.display()))?,
        (None, Some(json)) => json.to_string(),
        (Some(_), Some(_)) => {
            return Err(eyre::eyre!(
                "both --config and --config-json / RELAY_CONFIG provided; use only one"
            ));
        }
        (None, None) => {
            return Err(eyre::eyre!(
                "one of --config (RELAY_CONFIG_FILE) or --config-json (RELAY_CONFIG) must be provided"
            ));
        }
    };

    let contents = expand_env_vars(&raw)?;

    let config: RelayConfig = serde_json::from_str(&contents)
        .map_err(|e| eyre::eyre!("failed to parse relay config: {e}"))?;

    // Validate adapter-specific required fields.
    for sat in &config.satellite_chains {
        if sat.adapter == AdapterType::EthereumMpt && sat.dispute_game_factory.is_none() {
            return Err(eyre::eyre!(
                "satellite `{}` (chain {}) uses ethereum_mpt adapter but is missing `dispute_game_factory`",
                sat.name,
                sat.chain_id
            ));
        }
    }

    Ok(config)
}

/// Builds a [`ProviderArgs`] for a satellite chain from its RPC URL
/// and the shared signer.
fn satellite_provider_args(rpc_url: &str, signer: &SignerArgs) -> ProviderArgs {
    ProviderArgs::new()
        .with_http_urls([rpc_url])
        .with_signer(signer.clone())
}

// ---------------------------------------------------------------------------
// Bridge from SourceConfig → WorldChainConfig (used by chain.rs)
// ---------------------------------------------------------------------------

/// Internal config struct consumed by [`WorldChain::new`].
pub struct WorldChainConfig {
    pub chain_id: u64,
    pub world_id_source: Address,
    pub oprf_key_registry: Address,
    pub credential_issuer_schema_registry: Address,
    pub world_id_registry: Address,
    pub bridge_interval: u64,
}

impl From<&SourceConfig> for WorldChainConfig {
    fn from(src: &SourceConfig) -> Self {
        Self {
            chain_id: src.chain_id,
            world_id_source: src.world_id_source,
            oprf_key_registry: src.oprf_key_registry,
            credential_issuer_schema_registry: src.issuer_schema_registry,
            world_id_registry: src.world_id_registry,
            bridge_interval: src.bridge_interval_secs,
        }
    }
}

// ---------------------------------------------------------------------------
// CLI run
// ---------------------------------------------------------------------------

impl Cli {
    pub async fn run(self) -> eyre::Result<()> {
        let shutdown = tokio::signal::ctrl_c();

        // Load the unified config (from file or inline JSON).
        let config = load_config(self.config.as_ref(), self.config_json.as_deref())?;

        // Build the World Chain (source) provider.
        let wc_provider_args =
            ProviderArgs::new().with_http_urls([config.source.rpc_url.as_str()]);
        let wc_provider = Arc::new(wc_provider_args.http().await?);

        let wc_config = WorldChainConfig::from(&config.source);
        let world_chain = chain::WorldChain::new(&wc_config, wc_provider.clone());

        // Build a signer for destination chain transactions.
        // The signer key is loaded from WALLET_PRIVATE_KEY env var (via secrets manager).
        let wallet_key = std::env::var("WALLET_PRIVATE_KEY").map_err(|_| {
            eyre::eyre!("WALLET_PRIVATE_KEY env var is required for signing relay transactions")
        })?;
        let shared_signer = SignerArgs::from_wallet(wallet_key);

        let mut engine = Engine::new(world_chain);

        // Spawn a satellite task for each configured chain.
        for sat_config in &config.satellite_chains {
            let provider_args = satellite_provider_args(&sat_config.rpc_url, &shared_signer);
            let provider = Arc::new(provider_args.http().await?);

            match sat_config.adapter {
                AdapterType::Permissioned => {
                    let satellite = PermissionedSatellite::new(
                        &sat_config.name,
                        config.source.chain_id,
                        sat_config,
                        provider,
                    );
                    engine.spawn_satellite(satellite);
                }
                AdapterType::EthereumMpt => {
                    let dispute_game_factory = sat_config
                        .dispute_game_factory
                        .expect("validated in load_config");

                    let satellite = EthereumMptSatellite::from_satellite_config(
                        &wc_config,
                        sat_config,
                        dispute_game_factory,
                        sat_config.game_type,
                        sat_config.require_finalized,
                        wc_provider.clone(),
                        provider,
                    );
                    engine.spawn_satellite(satellite);
                }
            }

            tracing::info!(
                name = %sat_config.name,
                adapter = %sat_config.adapter,
                chain_id = sat_config.chain_id,
                "registered satellite"
            );
        }

        if config.satellite_chains.is_empty() {
            tracing::warn!(
                "no satellite chains configured — relay will only track World Chain state"
            );
        }

        tokio::select! {
            result = engine.run() => result,
            _ = shutdown => {
                tracing::info!("received shutdown signal");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let json = r#"{
            "source": {
                "chain_id": 480,
                "rpc_url": "https://worldchain.example.com",
                "world_id_source": "0x1111111111111111111111111111111111111111",
                "world_id_registry": "0x2222222222222222222222222222222222222222",
                "oprf_key_registry": "0x3333333333333333333333333333333333333333",
                "issuer_schema_registry": "0x4444444444444444444444444444444444444444",
                "bridge_interval_secs": 1800
            },
            "satellite_chains": [
                {
                    "name": "sepolia",
                    "type": "ethereum_mpt",
                    "chain_id": 11155111,
                    "rpc_url": "https://eth-sepolia.example.com",
                    "source_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "gateway": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "satellite": "0xcccccccccccccccccccccccccccccccccccccccc",
                    "dispute_game_factory": "0xdddddddddddddddddddddddddddddddddddddddd",
                    "game_type": 0,
                    "require_finalized": false
                },
                {
                    "name": "base_sepolia",
                    "type": "permissioned",
                    "chain_id": 84532,
                    "rpc_url": "https://base-sepolia.example.com",
                    "source_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "gateway": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "satellite": "0xffffffffffffffffffffffffffffffffffffffff"
                }
            ]
        }"#;

        let config: RelayConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.source.chain_id, 480);
        assert_eq!(config.source.bridge_interval_secs, 1800);
        assert_eq!(config.satellite_chains.len(), 2);

        let sepolia = &config.satellite_chains[0];
        assert_eq!(sepolia.name, "sepolia");
        assert_eq!(sepolia.adapter, AdapterType::EthereumMpt);
        assert!(sepolia.dispute_game_factory.is_some());

        let base = &config.satellite_chains[1];
        assert_eq!(base.name, "base_sepolia");
        assert_eq!(base.adapter, AdapterType::Permissioned);
        assert!(base.dispute_game_factory.is_none());
    }

    #[test]
    fn defaults_applied() {
        let json = r#"{
            "source": {
                "rpc_url": "https://worldchain.example.com",
                "world_id_source": "0x1111111111111111111111111111111111111111",
                "world_id_registry": "0x2222222222222222222222222222222222222222",
                "oprf_key_registry": "0x3333333333333333333333333333333333333333",
                "issuer_schema_registry": "0x4444444444444444444444444444444444444444"
            },
            "satellite_chains": []
        }"#;

        let config: RelayConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.source.chain_id, 480);
        assert_eq!(config.source.bridge_interval_secs, 3600);
    }
}
