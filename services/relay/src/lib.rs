pub mod config;
pub mod contracts;
pub mod error;
pub mod proof;
pub mod relay;
pub mod source;

use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use config::Config;
use relay::{DestinationContext, GatewayContext, RelayContext};
use tracing::{error, info};

/// Main entry point for the relay service.
pub async fn run(config: Config) -> eyre::Result<()> {
    info!("starting world-id-relay");

    // Build World Chain provider (with signer for propagateState)
    let wc_provider = build_provider_with_signer(&config).await?;

    // Build L1 provider (with signer for gateway.sendMessage)
    let l1_provider = match &config.l1_rpc_url {
        Some(url) => {
            let provider = build_provider_with_signer_for_url(url, &config).await?;
            Some(provider)
        }
        None => None,
    };

    // Build destination chain providers
    let destinations_config = config.load_destinations()?;
    let mut destinations = Vec::new();
    for dest_config in &destinations_config {
        let provider = build_provider_with_signer_for_url(&dest_config.rpc_url, &config).await?;
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

    // Build relay context
    let relay_ctx = RelayContext {
        wc_provider: build_readonly_provider(&config.wc_rpc_url)?,
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

/// Builds a DynProvider with signer for the World Chain RPC.
async fn build_provider_with_signer(config: &Config) -> eyre::Result<DynProvider> {
    let signer = config.signer.signer(&config.wc_rpc_url).await?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(config.wc_rpc_url.clone());
    Ok(provider.erased())
}

/// Builds a DynProvider with signer for a given RPC URL.
async fn build_provider_with_signer_for_url(
    url: &url::Url,
    config: &Config,
) -> eyre::Result<DynProvider> {
    let signer = config.signer.signer(url).await?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(url.clone());
    Ok(provider.erased())
}

/// Builds a read-only DynProvider (no signer).
fn build_readonly_provider(url: &url::Url) -> eyre::Result<DynProvider> {
    let provider = ProviderBuilder::new().connect_http(url.clone());
    Ok(provider.erased())
}
