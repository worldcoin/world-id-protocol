use std::sync::Arc;

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
    /// Relay config as a JSON string.
    #[arg(long, env = "RELAY_CONFIG")]
    pub config: String,
}

// ---------------------------------------------------------------------------
// Config file schema
// ---------------------------------------------------------------------------

/// Top-level relay configuration, passed as a JSON string via the
/// `RELAY_CONFIG` environment variable or `--config` CLI arg.
///
/// # RPC URL resolution
///
/// RPC endpoints are **not** specified in the config. Instead, they are
/// resolved automatically from environment variables based on the chain name:
///
/// - **Source chain**: reads `WORLDCHAIN_RPC_URL`
/// - **Satellite chains**: reads `{NAME}_RPC_URL` where `{NAME}` is the
///   satellite's `name` field converted to **UPPER_CASE**.
///
/// For example, a satellite with `"name": "SEPOLIA"` reads `SEPOLIA_RPC_URL`,
/// and `"name": "BASE_SEPOLIA"` reads `BASE_SEPOLIA_RPC_URL`.
///
/// This convention keeps secret RPC URLs out of the config and lets them be
/// injected via a secrets manager (e.g. AWS Secrets Manager → env vars in k8s).
///
/// # Example config
///
/// ```json
/// {
///   "source": {
///     "chain_id": 480,
///     "world_id_source": "0x...",
///     "world_id_registry": "0x...",
///     "oprf_key_registry": "0x...",
///     "issuer_schema_registry": "0x...",
///     "bridge_interval_secs": 3600
///   },
///   "permissioned_gateways": [
///     {
///       "name": "BASE_SEPOLIA",
///       "destination_chain_id": 84532,
///       "gateway": "0x...",
///       "satellite": "0x..."
///     }
///   ],
///   "ethereum_mpt_gateways": [
///     {
///       "name": "SEPOLIA",
///       "destination_chain_id": 11155111,
///       "gateway": "0x...",
///       "satellite": "0x...",
///       "dispute_game_factory": "0x...",
///       "game_type": 0,
///       "require_finalized": false
///     }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    /// World Chain (source of truth) configuration.
    pub source: SourceConfig,

    /// Permissioned gateway satellites (owner-attested chain head, no proofs).
    #[serde(default)]
    pub permissioned_gateways: Option<Vec<PermissionedGatewayConfig>>,

    /// Ethereum MPT gateway satellites (OP Stack dispute game + MPT proofs).
    #[serde(default)]
    pub ethereum_mpt_gateways: Option<Vec<EthereumMptGatewayConfig>>,
}

/// World Chain source configuration.
///
/// The RPC endpoint is read from the `WORLDCHAIN_RPC_URL` environment variable
/// (not from the config).
#[derive(Debug, Clone, Deserialize)]
pub struct SourceConfig {
    /// Chain ID of the source chain (default: 480 for World Chain).
    #[serde(default = "default_source_chain_id")]
    pub chain_id: u64,

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

/// Configuration for a permissioned gateway satellite.
///
/// Uses owner-attested chain head relayed from World Chain (no proofs required).
/// The relay operator is the gateway owner; source is always World Chain.
///
/// The RPC endpoint is derived from the `name` field: the env var
/// `{NAME}_RPC_URL` is read at startup (e.g. `BASE_SEPOLIA_RPC_URL`).
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionedGatewayConfig {
    /// Satellite identifier, also used to derive the RPC URL env var.
    ///
    /// The relay reads `{name}_RPC_URL` from the environment to get the
    /// RPC endpoint. Use UPPER_CASE (e.g. `"BASE_SEPOLIA"`).
    pub name: String,

    /// The destination chain ID.
    pub destination_chain_id: u64,

    /// The ERC-7786 gateway address on the destination chain.
    pub gateway: Address,

    /// The WorldIDSatellite (bridge) proxy address on the destination chain.
    pub satellite: Address,
}

/// Configuration for an Ethereum MPT gateway satellite.
///
/// Uses OP Stack dispute game + MPT storage proofs to bridge state to L1.
///
/// The RPC endpoint is derived from the `name` field: the env var
/// `{NAME}_RPC_URL` is read at startup (e.g. `SEPOLIA_RPC_URL`).
#[derive(Debug, Clone, Deserialize)]
pub struct EthereumMptGatewayConfig {
    /// Satellite identifier, also used to derive the RPC URL env var.
    ///
    /// The relay reads `{name}_RPC_URL` from the environment to get the
    /// RPC endpoint. Use UPPER_CASE (e.g. `"SEPOLIA"`).
    pub name: String,

    /// The destination chain ID.
    pub destination_chain_id: u64,

    /// The ERC-7786 gateway address on the destination chain.
    pub gateway: Address,

    /// The WorldIDSatellite (bridge) proxy address on the destination chain.
    pub satellite: Address,

    /// The DisputeGameFactory contract on the destination chain.
    pub dispute_game_factory: Address,

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

/// Parses the relay config from a JSON string.
fn parse_config(json: &str) -> eyre::Result<RelayConfig> {
    serde_json::from_str(json).map_err(|e| eyre::eyre!("failed to parse relay config: {e}"))
}

/// The env var name used for the World Chain (source) RPC endpoint.
const SOURCE_RPC_ENV: &str = "WORLDCHAIN_RPC_URL";

/// Reads an RPC URL from the environment.
///
/// For the source chain this is `WORLDCHAIN_RPC_URL`. For satellite chains
/// the var name is `{name}_RPC_URL` (e.g. `SEPOLIA_RPC_URL`).
fn rpc_url_from_env(env_var: &str) -> eyre::Result<String> {
    std::env::var(env_var).map_err(|_| {
        eyre::eyre!(
            "{env_var} env var is required but not set — \
             set it to the RPC endpoint for this chain"
        )
    })
}

impl PermissionedGatewayConfig {
    /// Returns the env var name that supplies this satellite's RPC URL.
    pub fn rpc_env_var(&self) -> String {
        format!("{}_RPC_URL", self.name.to_uppercase())
    }
}

impl EthereumMptGatewayConfig {
    /// Returns the env var name that supplies this satellite's RPC URL.
    pub fn rpc_env_var(&self) -> String {
        format!("{}_RPC_URL", self.name.to_uppercase())
    }
}

/// Builds a [`ProviderArgs`] from a chain name and shared signer, reading the
/// RPC URL from the `{NAME}_RPC_URL` environment variable.
fn satellite_provider_args(name: &str, signer: &SignerArgs) -> eyre::Result<ProviderArgs> {
    let env_var = format!("{}_RPC_URL", name.to_uppercase());
    let rpc_url = rpc_url_from_env(&env_var)?;
    Ok(ProviderArgs::new()
        .with_http_urls([rpc_url.as_str()])
        .with_signer(signer.clone()))
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

        let config = parse_config(&self.config)?;

        // Build a signer for relay transactions.
        // The signer key is loaded from WALLET_PRIVATE_KEY env var (via secrets manager).
        let wallet_key = std::env::var("WALLET_PRIVATE_KEY").map_err(|_| {
            eyre::eyre!("WALLET_PRIVATE_KEY env var is required for signing relay transactions")
        })?;
        let shared_signer = SignerArgs::from_wallet(wallet_key);

        // Build the World Chain (source) provider from WORLDCHAIN_RPC_URL.
        let wc_rpc_url = rpc_url_from_env(SOURCE_RPC_ENV)?;
        let wc_provider_args = ProviderArgs::new()
            .with_http_urls([wc_rpc_url.as_str()])
            .with_signer(shared_signer.clone());
        let wc_provider = Arc::new(wc_provider_args.http().await?);

        let wc_config = WorldChainConfig::from(&config.source);
        let world_chain = chain::WorldChain::new(&wc_config, wc_provider.clone());

        let mut engine = Engine::new(world_chain);
        let mut satellite_count = 0usize;

        // Spawn permissioned gateway satellites.
        for sat_config in config.permissioned_gateways.iter().flatten() {
            let provider_args = satellite_provider_args(&sat_config.name, &shared_signer)?;
            let provider = Arc::new(provider_args.http().await?);

            let satellite = PermissionedSatellite::new(
                &sat_config.name,
                config.source.chain_id,
                sat_config,
                provider,
            );
            engine.spawn_satellite(satellite);
            satellite_count += 1;

            tracing::info!(
                name = %sat_config.name,
                adapter = "permissioned_worldchain",
                chain_id = sat_config.destination_chain_id,
                "registered satellite"
            );
        }

        // Spawn Ethereum MPT gateway satellites.
        for sat_config in config.ethereum_mpt_gateways.iter().flatten() {
            let provider_args = satellite_provider_args(&sat_config.name, &shared_signer)?;
            let provider = Arc::new(provider_args.http().await?);

            let satellite = EthereumMptSatellite::from_config(
                &wc_config,
                sat_config,
                wc_provider.clone(),
                provider,
            );
            engine.spawn_satellite(satellite);
            satellite_count += 1;

            tracing::info!(
                name = %sat_config.name,
                adapter = "ethereum_mpt",
                chain_id = sat_config.destination_chain_id,
                "registered satellite"
            );
        }

        if satellite_count == 0 {
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
                "world_id_source": "0x1111111111111111111111111111111111111111",
                "world_id_registry": "0x2222222222222222222222222222222222222222",
                "oprf_key_registry": "0x3333333333333333333333333333333333333333",
                "issuer_schema_registry": "0x4444444444444444444444444444444444444444",
                "bridge_interval_secs": 1800
            },
            "ethereum_mpt_gateways": [
                {
                    "name": "SEPOLIA",
                    "destination_chain_id": 11155111,
                    "gateway": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "satellite": "0xcccccccccccccccccccccccccccccccccccccccc",
                    "dispute_game_factory": "0xdddddddddddddddddddddddddddddddddddddddd",
                    "game_type": 0,
                    "require_finalized": false
                }
            ],
            "permissioned_gateways": [
                {
                    "name": "BASE_SEPOLIA",
                    "destination_chain_id": 84532,
                    "gateway": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "satellite": "0xffffffffffffffffffffffffffffffffffffffff"
                }
            ]
        }"#;

        let config: RelayConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.source.chain_id, 480);
        assert_eq!(config.source.bridge_interval_secs, 1800);

        let mpt = config.ethereum_mpt_gateways.as_ref().unwrap();
        assert_eq!(mpt.len(), 1);
        assert_eq!(mpt[0].name, "SEPOLIA");
        assert_eq!(mpt[0].rpc_env_var(), "SEPOLIA_RPC_URL");
        assert_eq!(
            mpt[0].dispute_game_factory,
            "0xdddddddddddddddddddddddddddddddddddddddd"
                .parse::<Address>()
                .unwrap()
        );

        let perm = config.permissioned_gateways.as_ref().unwrap();
        assert_eq!(perm.len(), 1);
        assert_eq!(perm[0].name, "BASE_SEPOLIA");
        assert_eq!(perm[0].rpc_env_var(), "BASE_SEPOLIA_RPC_URL");
    }

    #[test]
    fn defaults_applied() {
        let json = r#"{
            "source": {
                "world_id_source": "0x1111111111111111111111111111111111111111",
                "world_id_registry": "0x2222222222222222222222222222222222222222",
                "oprf_key_registry": "0x3333333333333333333333333333333333333333",
                "issuer_schema_registry": "0x4444444444444444444444444444444444444444"
            }
        }"#;

        let config: RelayConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.source.chain_id, 480);
        assert_eq!(config.source.bridge_interval_secs, 3600);
        assert!(config.permissioned_gateways.is_none());
        assert!(config.ethereum_mpt_gateways.is_none());
    }
}
