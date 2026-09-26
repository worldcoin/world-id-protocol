use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, B256, Bytes},
    providers::DynProvider,
};
use eyre::Result;

use crate::{
    bindings::IWorldIDSatellite::IWorldIDSatelliteInstance,
    cli::{OpStackGatewayConfig, WorldChainConfig},
    primitives::ChainCommitment,
    proof::ethereum_mpt::build_l1_proof_attributes,
    relay::send_forward_to_l2_tx,
};

use super::Satellite;

/// Default poll interval when waiting for a dispute game.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Default timeout for dispute game polling.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3600);

/// A satellite that bridges to a native OP Stack L2 (Base, Optimism, …).
///
/// State is verified on L1 with the same dispute-game + MPT proof path as [`EthereumMptSatellite`],
/// then pushed from L1 to the L2 over the canonical `CrossDomainMessenger` by calling
/// `forwardToL2` on the L1 `EthereumMPTGatewayAdapter`. The relay transaction is sent on **L1**;
/// the destination chain head is read from the **L2** satellite.
///
/// [`EthereumMptSatellite`]: super::EthereumMptSatellite
pub struct OpStackSatellite {
    /// Human-readable name for logging (e.g. "op-stack-base").
    name: String,
    /// The destination (L2) chain ID.
    chain_id: u64,
    /// The `EthereumMPTGatewayAdapter` on L1 (`forwardToL2` is called here).
    l1_adapter: Address,
    /// The `L1CrossDomainMessenger` for the destination rollup.
    l1_messenger: Address,
    /// The `OpStackGatewayAdapter` on the destination L2.
    l2_adapter: Address,
    /// The `WorldIDSatellite` (bridge) on the destination L2.
    satellite: IWorldIDSatelliteInstance<Arc<DynProvider>>,
    /// L1 provider — used for dispute games and sending `forwardToL2`.
    l1_provider: Arc<DynProvider>,
    /// World Chain provider for fetching MPT proofs and block data.
    source_provider: Arc<DynProvider>,
    /// WorldIDSource address on World Chain.
    world_id_source: Address,
    /// DisputeGameFactory address on L1.
    dispute_game_factory: Address,
    /// The dispute game type to look for (e.g. 0 = CANNON).
    game_type: u32,
    /// Whether to require games to be finalized (DEFENDER_WINS) before using them.
    require_finalized: bool,
    /// Minimum L2 gas for the relayed `sendMessage` call.
    min_gas_limit: u32,
    /// How often to poll for a suitable dispute game.
    poll_interval: Duration,
    /// Maximum time to wait for a suitable dispute game.
    timeout: Duration,
}

impl OpStackSatellite {
    /// Creates a new OP Stack satellite from an [`OpStackGatewayConfig`] and providers.
    ///
    /// `l2_provider` reads the destination chain head; `l1_provider` sends `forwardToL2` and
    /// queries dispute games; `wc_provider` builds MPT proofs against World Chain state.
    pub fn from_config(
        wc_config: &WorldChainConfig,
        config: &OpStackGatewayConfig,
        wc_provider: Arc<DynProvider>,
        l1_provider: Arc<DynProvider>,
        l2_provider: Arc<DynProvider>,
    ) -> Self {
        Self {
            name: format!("op-stack-{}", config.name.to_lowercase()),
            chain_id: config.destination_chain_id,
            l1_adapter: config.l1_adapter,
            l1_messenger: config.l1_messenger,
            l2_adapter: config.l2_adapter,
            satellite: IWorldIDSatelliteInstance::new(config.satellite, l2_provider),
            l1_provider,
            source_provider: wc_provider,
            world_id_source: wc_config.world_id_source,
            dispute_game_factory: config.dispute_game_factory,
            game_type: config.game_type,
            require_finalized: config.require_finalized,
            min_gas_limit: config.min_gas_limit,
            poll_interval: DEFAULT_POLL_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl Satellite for OpStackSatellite {
    fn name(&self) -> &str {
        &self.name
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn remote_chain_head<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>> {
        Box::pin(async move {
            let result = self.satellite.KECCAK_CHAIN().call().await?;
            Ok(result.head)
        })
    }

    fn build_proof<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Bytes)>> + Send + 'a>> {
        Box::pin(async move {
            build_l1_proof_attributes(
                &self.source_provider,
                &self.l1_provider,
                self.world_id_source,
                self.dispute_game_factory,
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
            send_forward_to_l2_tx(
                &self.l1_provider,
                self.l1_adapter,
                self.l1_messenger,
                self.l2_adapter,
                self.chain_id,
                *self.satellite.address(),
                payload,
                attribute,
                self.min_gas_limit,
            )
            .await
        })
    }
}
