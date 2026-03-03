use std::{
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use alloy::providers::Provider;
use clap::Parser;
use eyre::Result;
use tracing::{error, info};

use world_id_relay::{
    cli::args::{DestinationConfig, GatewayConfig, WorldIDRelayConfig, load_destinations},
    engine::{Engine, WcRegistries},
    satellite::{EthereumMptSatellite, PermissionedSatellite, Satellite},
};

/// Default batch interval for `propagateState` calls (1 hour).
const DEFAULT_BATCH_INTERVAL: Duration = Duration::from_secs(3600);

/// Default commitment batch window (how long to accumulate `ChainCommitted` events).
const DEFAULT_COMMITMENT_BATCH_WINDOW: Duration = Duration::from_secs(30);

/// World Chain chain ID.
const WORLD_CHAIN_ID: u64 = 480;

/// Minimal CLI parsed by clap. The full [`WorldIDRelayConfig`] is loaded from
/// the TOML file (and env vars) via `TryFrom`, which avoids the clap field-name
/// collision between `WorldChainConfig::bridge` and `ChainConfig::bridge`.
#[derive(Parser)]
#[command(name = "world-id-relay", version, about = "World ID Bridge Relay Service")]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();

    info!("starting world-id-relay");

    let cli = Cli::parse();
    let config = WorldIDRelayConfig::try_from(cli.config.as_ref())?;

    // ── World Chain provider ─────────────────────────────────────────────────
    let wc_provider = config.world_chain.provider.clone().http().await?;
    info!("world chain provider connected");

    // ── Satellites ────────────────────────────────────────────────────────────
    let mut satellites: Vec<Arc<dyn Satellite>> = Vec::new();

    // Always create the Ethereum L1 MPT satellite from CLI/env config.
    let eth_config = &config.ethereum_chain;
    let l1_provider = eth_config.base.provider.clone().http().await?;
    let l1_chain_id = l1_provider.get_chain_id().await?;

    let eth_satellite = EthereumMptSatellite::new(
        "ethereum",
        l1_chain_id,
        eth_config.base.gateway,
        eth_config.base.bridge,
        WORLD_CHAIN_ID,
        l1_provider.clone(),
        wc_provider.clone(),
        config.world_chain.bridge,
        eth_config.dispute_game_factory,
        eth_config.game_type,
        eth_config.require_finalized,
    );

    satellites.push(Arc::new(eth_satellite));
    info!(chain_id = l1_chain_id, "added ethereum MPT satellite");

    // Load additional destination chains from a JSON config file.
    if let Some(ref dest_path) = config.destinations_config {
        let destinations = load_destinations(dest_path)?;
        info!(count = destinations.len(), path = %dest_path.display(), "loaded destinations config");

        for dest in destinations {
            build_destination_satellites(
                &mut satellites,
                dest,
                &wc_provider,
                config.world_chain.bridge,
                &config,
            )
            .await?;
        }
    }

    // CLI/env satellite chains (simple permissioned gateways).
    for chain_config in &config.satellite_chains {
        let provider = chain_config.provider.clone().http().await?;
        let chain_id = provider.get_chain_id().await?;
        let name = format!("permissioned-{chain_id}");

        let sat = PermissionedSatellite::new(
            &name,
            chain_id,
            chain_config.gateway,
            chain_config.bridge,
            WORLD_CHAIN_ID,
            provider,
        );

        info!(
            chain_id,
            name, "added permissioned satellite from CLI config"
        );
        satellites.push(Arc::new(sat));
    }

    if satellites.is_empty() {
        eyre::bail!("no destination satellites configured");
    }

    info!(count = satellites.len(), "all satellites initialized");

    // ── Engine ────────────────────────────────────────────────────────────────
    let registries = WcRegistries {
        source: config.world_chain.bridge,
        issuer_registry: config.world_chain.credential_issuer_schema_registry,
        oprf_registry: config.world_chain.oprf_key_registry,
        rp_registry: config.world_chain.world_id_registry,
    };

    let batch_interval = config
        .batch_interval_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BATCH_INTERVAL);

    let commitment_batch_window = config
        .commitment_batch_window_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_COMMITMENT_BATCH_WINDOW);

    let engine = Engine::new(
        wc_provider,
        registries,
        satellites,
        batch_interval,
        commitment_batch_window,
    );

    // Blocks forever under normal operation.
    if let Err(e) = engine.run().await {
        error!(error = %e, "relay engine terminated with error");
        return Err(e);
    }

    Ok(())
}

/// Build satellite instances for a single destination chain from the JSON config.
async fn build_destination_satellites(
    satellites: &mut Vec<Arc<dyn Satellite>>,
    dest: DestinationConfig,
    wc_provider: &alloy::providers::DynProvider,
    wc_source_address: alloy::primitives::Address,
    config: &WorldIDRelayConfig,
) -> Result<()> {
    use world_id_services_common::ProviderArgs;

    // Build a provider for the destination chain. Re-use the relay wallet signer
    // when available so the relay can submit transactions.
    let mut dest_provider_args = ProviderArgs::new().with_http_urls([dest.rpc_url.as_str()]);

    if let Some(ref signer) = config.world_chain.provider.signer {
        dest_provider_args.signer = Some(signer.clone());
    }

    let dest_provider = dest_provider_args.http().await?;

    for gw in dest.gateways {
        match gw {
            GatewayConfig::Permissioned { address, bridge } => {
                let name = format!("permissioned-{}", dest.chain_id);

                let sat = PermissionedSatellite::new(
                    &name,
                    dest.chain_id,
                    address,
                    bridge,
                    WORLD_CHAIN_ID,
                    dest_provider.clone(),
                );

                info!(chain_id = dest.chain_id, gateway = %address, "added permissioned satellite");
                satellites.push(Arc::new(sat));
            }

            GatewayConfig::EthereumMpt {
                address,
                bridge,
                dispute_game_factory,
                game_type,
                require_finalized,
            } => {
                let name = format!("ethereum-mpt-{}", dest.chain_id);

                let sat = EthereumMptSatellite::new(
                    &name,
                    dest.chain_id,
                    address,
                    bridge,
                    WORLD_CHAIN_ID,
                    dest_provider.clone(),
                    wc_provider.clone(),
                    wc_source_address,
                    dispute_game_factory,
                    game_type,
                    require_finalized,
                );

                info!(chain_id = dest.chain_id, gateway = %address, "added ethereum MPT satellite");
                satellites.push(Arc::new(sat));
            }

            GatewayConfig::LightClient {
                address,
                bridge: _,
                l1_bridge_address: _,
                helios_prover_url: _,
            } => {
                // Light client satellite is not yet implemented at runtime.
                info!(
                    chain_id = dest.chain_id,
                    gateway = %address,
                    "light client satellite configured (not yet supported at runtime)"
                );
            }
        }
    }

    Ok(())
}
