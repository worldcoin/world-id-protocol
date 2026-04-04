use std::{future::Future, pin::Pin, sync::Arc};

use alloy::{
    primitives::{Address, B256, Bytes},
    providers::DynProvider,
};
use eyre::Result;

use crate::{
    bindings::{IGateway::IGatewayInstance, IWorldIDSatellite::IWorldIDSatelliteInstance},
    cli::PermissionedGatewayConfig,
    primitives::ChainCommitment,
    relay::send_relay_tx,
    satellite::Satellite,
};

use super::build_chain_head_attribute;

/// A satellite that uses the Permissioned gateway (owner-attested chain head)
/// on standard EVM-compatible chains.
///
/// The simplest proof path: the relay operator is the gateway owner, so `build_proof`
/// just encodes `chainHead(bytes32)` as the attribute. No MPT proofs or ZK proofs.
pub struct PermissionedSatellite {
    /// Human-readable name for logging.
    name: String,
    /// The destination chain ID.
    chain_id: u64,
    /// The gateway contract on the destination chain.
    gateway: IGatewayInstance<Arc<DynProvider>>,
    /// The satellite (bridge) contract on the destination chain.
    satellite: IWorldIDSatelliteInstance<Arc<DynProvider>>,
    /// The satellite (bridge) contract address on the destination chain.
    satellite_address: Address,
    /// The chain ID of the anchor (source) chain, used for ERC-7930 address encoding.
    anchor_chain_id: u64,
    /// Destination chain provider for sending relay transactions.
    provider: Arc<DynProvider>,
}

impl PermissionedSatellite {
    /// Creates a new permissioned satellite from a gateway config and provider.
    pub fn new(
        name: impl Into<String>,
        anchor_chain_id: u64,
        config: &PermissionedGatewayConfig,
        provider: Arc<DynProvider>,
    ) -> Self {
        Self {
            name: name.into(),
            chain_id: config.destination_chain_id,
            gateway: IGatewayInstance::new(config.gateway, provider.clone()),
            satellite: IWorldIDSatelliteInstance::new(config.satellite, provider.clone()),
            satellite_address: config.satellite,
            anchor_chain_id,
            provider,
        }
    }
}

impl Satellite for PermissionedSatellite {
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
            let attribute = build_chain_head_attribute(commitment.chain_head);
            let payload = commitment.commitment_payload.clone();
            Ok((attribute, payload))
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
                self.satellite_address,
                self.anchor_chain_id,
                payload,
                attribute,
            )
            .await
        })
    }
}
