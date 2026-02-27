use std::{future::Future, pin::Pin, time::Duration};

use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::DynProvider;
use eyre::Result;

use crate::proof::ChainCommitment;
use crate::proof::ethereum_mpt::build_l1_proof_attributes;
use crate::relay::send_relay_tx;

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
    name: String,
    chain_id: u64,
    gateway_address: Address,
    bridge_address: Address,
    /// The chain ID of the anchor (source) chain, used for ERC-7930 address encoding.
    anchor_chain_id: u64,
    /// L1 provider for sending the relay transaction.
    provider: DynProvider,
    /// World Chain provider for fetching MPT proofs and block data.
    wc_provider: DynProvider,
    /// WorldIDSource contract address on World Chain.
    wc_source_address: Address,
    /// DisputeGameFactory contract address on L1.
    dispute_game_factory: Address,
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
    /// Creates a new Ethereum MPT satellite with default poll interval and timeout.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for logging.
    /// * `chain_id` - The L1 chain ID.
    /// * `gateway` - The Ethereum MPT gateway contract address on L1.
    /// * `bridge` - The satellite bridge contract address on L1.
    /// * `anchor_chain_id` - The chain ID of World Chain (source).
    /// * `provider` - An L1 provider with signing capability.
    /// * `wc_provider` - A World Chain provider for MPT proof fetching.
    /// * `wc_source_address` - The WorldIDSource contract address on World Chain.
    /// * `dispute_game_factory` - The DisputeGameFactory address on L1.
    /// * `game_type` - The dispute game type to use.
    /// * `require_finalized` - Whether to require DEFENDER_WINS before relaying.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        chain_id: u64,
        gateway: Address,
        bridge: Address,
        anchor_chain_id: u64,
        provider: DynProvider,
        wc_provider: DynProvider,
        wc_source_address: Address,
        dispute_game_factory: Address,
        game_type: u32,
        require_finalized: bool,
    ) -> Self {
        Self {
            name: name.into(),
            chain_id,
            gateway_address: gateway,
            bridge_address: bridge,
            anchor_chain_id,
            provider,
            wc_provider,
            wc_source_address,
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
        self.gateway_address
    }

    fn bridge(&self) -> Address {
        self.bridge_address
    }

    fn build_proof<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Bytes)>> + Send + 'a>> {
        Box::pin(async move {
            build_l1_proof_attributes(
                &self.wc_provider,
                &self.provider,
                self.wc_source_address,
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
            send_relay_tx(
                &self.provider,
                self.gateway_address,
                self.bridge_address,
                self.anchor_chain_id,
                payload,
                attribute,
            )
            .await
        })
    }
}
