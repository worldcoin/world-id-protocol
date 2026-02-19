mod bindings;
pub mod config;
pub mod contracts;
pub mod error;
pub mod proof;
pub mod relay;
pub mod source;
// TODO: WIP CLI module — re-enable when chain.rs is complete.
mod cli;

use config::Config;
use relay::{DestinationContext, GatewayContext, RelayContext};
use tracing::{error, info};

/// Main entry point for the relay service.
pub async fn run(config: Config) -> eyre::Result<()> {
    info!("starting world-id-relay");

    // Build World Chain provider (with signer, throttle, fallback from ProviderArgs)
    let wc_provider = config.provider.clone().http().await?;

    // Build L1 provider (same signer/throttle, different RPC URL)
    let l1_provider = match &config.l1_rpc_url {
        Some(url) => {
            let mut args = config.provider.clone();
            args.http = Some(vec![url.clone()]);
            Some(args.http().await?)
        }
        None => None,
    };

    // Build destination chain providers
    let destinations_config = config.load_destinations()?;
    let mut destinations = Vec::new();
    for dest_config in &destinations_config {
        let mut args = config.provider.clone();
        args.http = Some(vec![dest_config.rpc_url.clone()]);
        let provider = args.http().await?;
        destinations.push(DestinationContext {
            chain_id: dest_config.chain_id,
            provider,
            gateways: dest_config
                .gateways
                .iter()
                .map(|gw| GatewayContext {
                    gateway_type: gw.gateway_type,
                    address: gw.address,
                })
                .collect(),
        });
    }

    // Channel for source → relay communication
    let (tx, rx) = tokio::sync::mpsc::channel(32);

    // Build relay context (WC provider for read-only MPT proofs)
    let relay_wc_provider = config.provider.clone().http().await?;
    let relay_ctx = RelayContext {
        wc_provider: relay_wc_provider,
        wc_source_address: config.wc_source_address,
        l1_provider,
        l1_gateway_address: config.l1_gateway_address,
        l1_satellite_address: config.l1_satellite_address,
        dispute_game_factory: config.dispute_game_factory,
        game_type: config.game_type,
        require_finalized: config.require_finalized,
        dispute_game_poll_interval: config.dispute_game_poll_interval.into(),
        dispute_game_timeout: config.dispute_game_timeout.into(),
        destinations,
        helios_prover_url: config.helios_prover_url.clone(),
    };

    // Spawn source and relay tasks
    let source_handle = tokio::spawn(source::run_source(
        wc_provider,
        config.wc_source_address,
        config.issuer_schema_ids.clone(),
        config.oprf_key_ids.clone(),
        config.propagation_interval.into(),
        config.event_poll_interval.into(),
        tx,
    ));

    let relay_handle = tokio::spawn(relay::run_relay(relay_ctx, rx));

    // Wait for either task to finish or Ctrl+C
    tokio::select! {
        result = source_handle => {
            error!("source task exited: {:?}", result);
        }
        result = relay_handle => {
            error!("relay task exited: {:?}", result);
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    info!("world-id-relay shutting down");
    Ok(())
}
