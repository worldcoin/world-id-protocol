use clap::Parser;
use serde::Deserialize;

use std::path::PathBuf;

use alloy_primitives::Address;
use clap::Parser;
use serde::Deserialize;
use url::Url;
use world_id_services_common::ProviderArgs;

/// World ID Bridge Relay Service.
#[derive(clap::Parser, Debug)]
#[command(name = "world-id-relay", version, about)]
pub struct Config {
    // ── Source chain (World Chain) ──────────────────────────────────────
    /// WorldIDSource proxy address on World Chain.
    #[arg(long, env = "WC_SOURCE_ADDRESS")]
    pub wc_source_address: Address,

    /// Issuer schema IDs to track (comma-separated).
    #[arg(long, env = "ISSUER_SCHEMA_IDS", value_delimiter = ',')]
    pub issuer_schema_ids: Vec<u64>,

    /// OPRF key IDs to track (comma-separated).
    #[arg(long, env = "OPRF_KEY_IDS", value_delimiter = ',')]
    pub oprf_key_ids: Vec<u64>,

    /// How often to call propagateState() (e.g. "1h", "30m", "3600s").
    #[arg(long, env = "PROPAGATION_INTERVAL", default_value = "1h")]
    pub propagation_interval: humantime::Duration,

    // ── Provider (RPC + signer + throttle) ─────────────────────────────
    /// World Chain RPC, signer, and throttle configuration.
    #[command(flatten)]
    pub provider: ProviderArgs,

    // ── L1 (Ethereum) ──────────────────────────────────────────────────
    /// Ethereum L1 RPC URL. Required for EthereumMPT relay.
    #[arg(long, env = "L1_RPC_URL")]
    pub l1_rpc_url: Option<Url>,

    /// EthereumMPTGatewayAdapter address on L1.
    #[arg(long, env = "L1_GATEWAY_ADDRESS")]
    pub l1_gateway_address: Option<Address>,

    /// WorldIDSatellite address on L1 (the bridge that receives state).
    #[arg(long, env = "L1_SATELLITE_ADDRESS")]
    pub l1_satellite_address: Option<Address>,

    /// DisputeGameFactory address on L1.
    #[arg(long, env = "DISPUTE_GAME_FACTORY")]
    pub dispute_game_factory: Option<Address>,

    /// OP Stack dispute game type (default: 0 = CANNON).
    #[arg(long, env = "GAME_TYPE", default_value_t = 0)]
    pub game_type: u32,

    /// Require dispute game to be finalized (DEFENDER_WINS) before relaying.
    #[arg(long, env = "REQUIRE_FINALIZED", default_value_t = false)]
    pub require_finalized: bool,

    // ── Destination chains ─────────────────────────────────────────────
    /// Path to JSON file configuring destination chain gateways.
    #[arg(long, env = "DESTINATIONS_CONFIG")]
    pub destinations_config: Option<PathBuf>,

    // ── Tuning ─────────────────────────────────────────────────────────
    /// How often to poll for a matching dispute game.
    #[arg(long, env = "DISPUTE_GAME_POLL_INTERVAL", default_value = "60s")]
    pub dispute_game_poll_interval: humantime::Duration,

    /// Max time to wait for a dispute game covering the target block.
    #[arg(long, env = "DISPUTE_GAME_TIMEOUT", default_value = "4h")]
    pub dispute_game_timeout: humantime::Duration,

    /// URL of the Helios SP1 prover service. Required for LightClient relay.
    #[arg(long, env = "HELIOS_PROVER_URL")]
    pub helios_prover_url: Option<Url>,

    /// How often to poll WC for new ChainCommitted events (block time).
    #[arg(long, env = "EVENT_POLL_INTERVAL", default_value = "12s")]
    pub event_poll_interval: humantime::Duration,
}

/// Configuration for a single destination chain.
#[derive(Debug, Clone, Deserialize)]
pub struct DestinationChain {
    pub chain_id: u64,
    pub rpc_url: Url,
    pub gateways: Vec<GatewayConfig>,
}

/// Configuration for a single gateway on a destination chain.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    #[serde(rename = "type")]
    pub gateway_type: GatewayType,
    pub address: Address,
}
