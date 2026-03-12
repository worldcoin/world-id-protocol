use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, B256, Bytes},
    providers::DynProvider,
};
use eyre::Result;

use crate::{
    bindings::{
        IDisputeGameFactory::IDisputeGameFactoryInstance, IGateway::IGatewayInstance,
        IWorldIDSatellite::IWorldIDSatelliteInstance, IWorldIDSource::IWorldIDSourceInstance,
    },
    cli::{SatelliteConfig, WorldChainConfig},
    primitives::ChainCommitment,
    proof::ethereum_mpt::build_l1_proof_attributes,
    relay::send_relay_tx,
};

use super::Satellite;

/// Default poll interval when waiting for a dispute game.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Default timeout for dispute game polling.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3600);

/// A satellite that uses the Ethereum MPT gateway (L1 DisputeGame + MPT proofs).
///
/// This is the most complex proof path. It waits for an OP Stack dispute game that covers
/// the target World Chain block, then constructs MPT storage proofs against the game's
/// proven state root. The relay transaction is sent on L1.
pub struct EthereumMptSatellite {
    /// Human-readable name for logging (e.g. "ethereum-mainnet", "base-sepolia").
    name: String,
    /// The L1 chain ID for this satellite (e.g. 1 for mainnet, 11155111 for sepolia).
    chain_id: u64,
    /// The gateway contract on L1.
    gateway: IGatewayInstance<Arc<DynProvider>>,
    /// The satellite (bridge) contract on L1.
    satellite: IWorldIDSatelliteInstance<Arc<DynProvider>>,
    /// The chain ID of the anchor (source) chain, used for ERC-7930 address encoding.
    anchor_chain_id: u64,
    /// L1 provider -- kept separately for raw `send_transaction` calls in `send_relay_tx`.
    provider: Arc<DynProvider>,
    /// World Chain provider for fetching MPT proofs and block data.
    source_provider: Arc<DynProvider>,
    /// WorldIDSource contract on World Chain.
    world_id_source: IWorldIDSourceInstance<Arc<DynProvider>>,
    /// DisputeGameFactory contract on L1.
    dispute_game_factory: IDisputeGameFactoryInstance<Arc<DynProvider>>,
    /// The dispute game type to look for (e.g. 0 = CANNON).
    game_type: u32,
    /// Whether to require games to be finalized (DEFENDER_WINS) before using them.
    require_finalized: bool,
    /// How often to poll for a suitable dispute game.
    poll_interval: Duration,
    /// Maximum time to wait for a suitable dispute game.
    timeout: Duration,
}

impl EthereumMptSatellite {
    /// Creates a new Ethereum MPT satellite from a `SatelliteConfig` and pre-built providers.
    pub fn from_satellite_config(
        wc_config: &WorldChainConfig,
        sat_config: &SatelliteConfig,
        dispute_game_factory: Address,
        game_type: u32,
        require_finalized: bool,
        wc_provider: Arc<DynProvider>,
        eth_provider: Arc<DynProvider>,
    ) -> Self {
        Self {
            name: format!("ethereum-mpt-{}", sat_config.chain_id),
            chain_id: sat_config.chain_id,
            gateway: IGatewayInstance::new(sat_config.gateway, eth_provider.clone()),
            satellite: IWorldIDSatelliteInstance::new(
                sat_config.satellite,
                eth_provider.clone(),
            ),
            anchor_chain_id: wc_config.chain_id,
            provider: eth_provider.clone(),
            source_provider: wc_provider.clone(),
            world_id_source: IWorldIDSourceInstance::new(wc_config.world_id_source, wc_provider),
            dispute_game_factory: IDisputeGameFactoryInstance::new(
                dispute_game_factory,
                eth_provider,
            ),
            game_type,
            require_finalized,
            poll_interval: DEFAULT_POLL_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl Satellite for EthereumMptSatellite {
    fn name(&self) -> &str {
        &self.name
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn build_proof<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Bytes)>> + Send + 'a>> {
        Box::pin(async move {
            build_l1_proof_attributes(
                &self.source_provider,
                &self.provider,
                *self.world_id_source.address(),
                *self.dispute_game_factory.address(),
                self.game_type,
                self.require_finalized,
                commitment,
                self.poll_interval,
                self.timeout,
            )
            .await
        })
    }

    fn relay<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>> {
        Box::pin(async move {
            let (attribute, payload) = self.build_proof(commitment).await?;
            send_relay_tx(
                &self.provider,
                *self.gateway.address(),
                *self.satellite.address(),
                self.anchor_chain_id,
                payload,
                attribute,
            )
            .await
        })
    }
}
