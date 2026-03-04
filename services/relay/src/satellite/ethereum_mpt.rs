use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, B256, Bytes},
    providers::{DynProvider, Provider},
};
use eyre::Result;

use crate::{
    bindings::{
        IDisputeGameFactory::IDisputeGameFactoryInstance, IGateway::IGatewayInstance,
        IWorldIDSatellite::IWorldIDSatelliteInstance, IWorldIDSource::IWorldIDSourceInstance,
    },
    proof::{ChainCommitment, ethereum_mpt::build_l1_proof_attributes},
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
pub struct EthereumMptSatellite<P: Provider = Arc<DynProvider>> {
    /// Human-readable name for logging (e.g. "ethereum-mainnet", "base-sepolia").
    name: String,
    /// The L1 chain ID for this satellite (e.g. 1 for mainnet, 11155111 for sepolia).
    chain_id: u64,
    /// The gateway contract address on L1.
    gateway: IGatewayInstance<P>,
    /// The satellite (bridge) contract address on L1.
    satellite: IWorldIDSatelliteInstance<P>,
    /// The chain ID of the anchor (source) chain, used for ERC-7930 address encoding.
    anchor_chain_id: u64,
    /// L1 provider for sending the relay transaction.
    provider: P,
    /// World Chain provider for fetching MPT proofs and block data.
    source_provider: P,
    /// WorldIDSource contract address on World Chain.
    world_id_source: IWorldIDSourceInstance<P>,
    /// DisputeGameFactory contract address on L1.
    dispute_game_factory: IDisputeGameFactoryInstance<P>,
    /// The dispute game type to look for (e.g. 0 = CANNON).
    game_type: u32,
    /// Whether to require games to be finalized (DEFENDER_WINS) before using them.
    require_finalized: bool,
    /// How often to poll for a suitable dispute game.
    poll_interval: Duration,
    /// Maximum time to wait for a suitable dispute game.
    timeout: Duration,
}

impl<P: Provider> EthereumMptSatellite<P> {
    /// Creates a new Ethereum MPT satellite with default poll interval and timeout.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        chain_id: u64,
        gateway: IGatewayInstance<P>,
        bridge: IWorldIDSatelliteInstance<P>,
        anchor_chain_id: u64,
        provider: P,
        source_provider: P,
        world_id_source: IWorldIDSourceInstance<P>,
        dispute_game_factory: IDisputeGameFactoryInstance<P>,
        game_type: u32,
        require_finalized: bool,
    ) -> Self {
        Self {
            name: name.into(),
            chain_id,
            gateway,
            satellite: bridge,
            anchor_chain_id,
            provider,
            source_provider,
            world_id_source,
            dispute_game_factory,
            game_type,
            require_finalized,
            poll_interval: DEFAULT_POLL_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Overrides the poll interval used when waiting for a dispute game.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Overrides the maximum time to wait for a dispute game.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Satellite for EthereumMptSatellite {
    fn name(&self) -> &str {
        &self.name
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn gateway(&self) -> Address {
        *self.gateway.address()
    }

    fn bridge(&self) -> Address {
        *self.satellite.address()
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
