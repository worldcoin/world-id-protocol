use std::time::Duration;

use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{DynProvider, Provider},
};
use tracing::{error, info, warn};
use url::Url;

use crate::{
    config::GatewayType,
    contracts::IGateway,
    error::RelayError,
    proof::{ChainCommitment, ethereum_mpt, light_client, permissioned},
};

/// Relay context holding providers for all configured chains.
pub struct RelayContext {
    /// World Chain provider (read-only, for MPT proofs).
    pub wc_provider: DynProvider,
    /// World Chain source contract address.
    pub wc_source_address: Address,

    // L1 config (optional)
    pub l1_provider: Option<DynProvider>,
    pub l1_gateway_address: Option<Address>,
    pub l1_satellite_address: Option<Address>,
    pub dispute_game_factory: Option<Address>,
    pub game_type: u32,
    pub require_finalized: bool,
    pub dispute_game_poll_interval: Duration,
    pub dispute_game_timeout: Duration,

    // Destination chain providers
    pub destinations: Vec<DestinationContext>,

    // Helios prover URL
    pub helios_prover_url: Option<Url>,
}

pub struct DestinationContext {
    pub chain_id: u64,
    pub provider: DynProvider,
    pub gateways: Vec<GatewayContext>,
}

pub struct GatewayContext {
    pub gateway_type: GatewayType,
    pub address: Address,
}

/// Runs the relay loop, consuming ChainCommitment events and relaying to all gateways.
///
/// Gateway ordering: EthereumMPT (L1) first, then LightClient, then Permissioned.
pub async fn run_relay(
    ctx: RelayContext,
    mut rx: tokio::sync::mpsc::Receiver<ChainCommitment>,
) -> eyre::Result<()> {
    info!("relay loop started, waiting for commitments");

    while let Some(commitment) = rx.recv().await {
        info!(
            chain_head = %commitment.chain_head,
            block = commitment.block_number,
            "processing commitment"
        );

        // Step 1: Relay to L1 via EthereumMPT (if configured)
        if let (Some(l1_provider), Some(l1_gw), Some(dgf)) = (
            &ctx.l1_provider,
            &ctx.l1_gateway_address,
            &ctx.dispute_game_factory,
        ) {
            match relay_ethereum_mpt(
                &ctx.wc_provider,
                l1_provider,
                ctx.wc_source_address,
                *l1_gw,
                ctx.l1_satellite_address.unwrap_or_default(),
                *dgf,
                ctx.game_type,
                ctx.require_finalized,
                &commitment,
                ctx.dispute_game_poll_interval,
                ctx.dispute_game_timeout,
            )
            .await
            {
                Ok(()) => info!("L1 EthereumMPT relay succeeded"),
                Err(e) => {
                    error!(error = %e, "L1 EthereumMPT relay failed");
                    if !e.is_recoverable() {
                        continue;
                    }
                }
            }
        }

        // Step 2: Relay to each destination via LightClient (if configured)
        if let Some(helios_url) = &ctx.helios_prover_url {
            if let Some(l1_provider) = &ctx.l1_provider {
                for dest in &ctx.destinations {
                    for gw in &dest.gateways {
                        if gw.gateway_type != GatewayType::LightClient {
                            continue;
                        }

                        let l1_bridge = ctx.l1_satellite_address.unwrap_or_default();

                        match relay_light_client(
                            l1_provider,
                            &dest.provider,
                            l1_bridge,
                            gw.address,
                            helios_url,
                            &commitment,
                        )
                        .await
                        {
                            Ok(()) => info!(
                                chain_id = dest.chain_id,
                                gateway = %gw.address,
                                "LightClient relay succeeded"
                            ),
                            Err(e) => error!(
                                chain_id = dest.chain_id,
                                gateway = %gw.address,
                                error = %e,
                                "LightClient relay failed"
                            ),
                        }
                    }
                }
            }
        }

        // Step 3: Relay to each destination via Permissioned (if configured)
        for dest in &ctx.destinations {
            for gw in &dest.gateways {
                if gw.gateway_type != GatewayType::Permissioned {
                    continue;
                }

                match relay_permissioned(&dest.provider, gw.address, &commitment).await {
                    Ok(()) => info!(
                        chain_id = dest.chain_id,
                        gateway = %gw.address,
                        "Permissioned relay succeeded"
                    ),
                    Err(e) => error!(
                        chain_id = dest.chain_id,
                        gateway = %gw.address,
                        error = %e,
                        "Permissioned relay failed"
                    ),
                }
            }
        }

        info!(
            chain_head = %commitment.chain_head,
            "commitment relay cycle complete"
        );
    }

    warn!("source channel closed, relay loop exiting");
    Ok(())
}

/// Relays a commitment to the L1 EthereumMPT gateway.
#[allow(clippy::too_many_arguments)]
async fn relay_ethereum_mpt(
    wc_provider: &DynProvider,
    l1_provider: &DynProvider,
    wc_source_address: Address,
    gateway_address: Address,
    satellite_address: Address,
    dispute_game_factory: Address,
    game_type: u32,
    require_finalized: bool,
    commitment: &ChainCommitment,
    poll_interval: Duration,
    timeout: Duration,
) -> Result<(), RelayError> {
    let (attribute, payload) = ethereum_mpt::build_l1_proof_attributes(
        wc_provider,
        l1_provider,
        wc_source_address,
        dispute_game_factory,
        game_type,
        require_finalized,
        commitment,
        poll_interval,
        timeout,
    )
    .await?;

    send_gateway_message(
        l1_provider,
        gateway_address,
        satellite_address,
        payload,
        attribute,
    )
    .await
}

/// Relays a commitment to a destination via LightClient gateway.
async fn relay_light_client(
    l1_provider: &DynProvider,
    dest_provider: &DynProvider,
    l1_bridge_address: Address,
    gateway_address: Address,
    helios_prover_url: &Url,
    commitment: &ChainCommitment,
) -> Result<(), RelayError> {
    let (attribute, payload) = light_client::build_light_client_proof_attributes(
        l1_provider,
        dest_provider,
        l1_bridge_address,
        gateway_address,
        helios_prover_url,
        commitment,
    )
    .await?;

    let gateway = IGateway::new(gateway_address, dest_provider);
    let satellite_address: Address = gateway.STATE_BRIDGE().call().await?;

    send_gateway_message(
        dest_provider,
        gateway_address,
        satellite_address,
        payload,
        attribute,
    )
    .await
}

/// Relays a commitment to a destination via Permissioned gateway.
async fn relay_permissioned(
    dest_provider: &DynProvider,
    gateway_address: Address,
    commitment: &ChainCommitment,
) -> Result<(), RelayError> {
    let (attribute, payload) = permissioned::build_permissioned_proof_attributes(commitment);

    let gateway = IGateway::new(gateway_address, dest_provider);
    let satellite_address: Address = gateway.STATE_BRIDGE().call().await?;

    send_gateway_message(
        dest_provider,
        gateway_address,
        satellite_address,
        payload,
        attribute,
    )
    .await
}

/// Sends `gateway.sendMessage(recipient, payload, attributes)`.
async fn send_gateway_message(
    provider: &DynProvider,
    gateway_address: Address,
    satellite_address: Address,
    payload: Bytes,
    attribute: Bytes,
) -> Result<(), RelayError> {
    let gateway = IGateway::new(gateway_address, provider);

    let chain_id = provider.get_chain_id().await.map_err(RelayError::Rpc)?;

    let recipient = format_evm_v1_address(chain_id, satellite_address);
    let attributes = vec![attribute];

    info!(
        gateway = %gateway_address,
        satellite = %satellite_address,
        "sending gateway message"
    );

    let tx = gateway.sendMessage(recipient, payload, attributes);

    let pending = tx
        .send()
        .await
        .map_err(|e| RelayError::ContractRevert(format!("{e}")))?;

    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| RelayError::ContractRevert(format!("{e}")))?;

    info!(
        tx_hash = %receipt.transaction_hash,
        gas_used = receipt.gas_used,
        "gateway message sent"
    );

    Ok(())
}

/// Formats an address as an ERC-7786 interoperable address.
/// On-chain: `abi.encodePacked(uint256(chainId), address)`
fn format_evm_v1_address(chain_id: u64, address: Address) -> Bytes {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    data.extend_from_slice(address.as_slice());
    Bytes::from(data)
}
