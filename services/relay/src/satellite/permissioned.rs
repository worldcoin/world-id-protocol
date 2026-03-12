use std::{future::Future, pin::Pin, sync::Arc};

use alloy::{
    primitives::{Address, B256, Bytes, keccak256},
    providers::DynProvider,
    sol_types::SolValue,
};
use eyre::Result;

use crate::{
    bindings::IGateway::IGatewayInstance,
    cli::SatelliteConfig,
    primitives::ChainCommitment,
    relay::send_relay_tx,
};

use super::Satellite;

/// A satellite that uses the Permissioned gateway (owner-attested chain head).
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
    /// The satellite (bridge) contract address on the destination chain.
    satellite_address: Address,
    /// The chain ID of the anchor (source) chain, used for ERC-7930 address encoding.
    anchor_chain_id: u64,
    /// Destination chain provider for sending relay transactions.
    provider: Arc<DynProvider>,
}

impl PermissionedSatellite {
    /// Creates a new permissioned satellite from a satellite config and provider.
    pub fn new(
        name: impl Into<String>,
        anchor_chain_id: u64,
        config: &SatelliteConfig,
        provider: Arc<DynProvider>,
    ) -> Self {
        Self {
            name: name.into(),
            chain_id: config.destination_chain_id,
            gateway: IGatewayInstance::new(config.gateway, provider.clone()),
            satellite_address: config.satellite,
            anchor_chain_id,
            provider,
        }
    }

    /// Builds the `chainHead(bytes32)` attribute for the permissioned gateway.
    fn build_attribute(chain_head: B256) -> Bytes {
        let selector = &keccak256(b"chainHead(bytes32)")[..4];
        let encoded_head = chain_head.abi_encode();
        let mut attribute = Vec::with_capacity(4 + encoded_head.len());
        attribute.extend_from_slice(selector);
        attribute.extend_from_slice(&encoded_head);
        attribute.into()
    }
}

impl Satellite for PermissionedSatellite {
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
            let attribute = Self::build_attribute(commitment.chain_head);
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn build_attribute_encodes_correctly() {
        let head = B256::from([0xAB; 32]);
        let attr = PermissionedSatellite::build_attribute(head);

        // First 4 bytes: selector
        let expected_selector = &keccak256(b"chainHead(bytes32)")[..4];
        assert_eq!(&attr[..4], expected_selector);

        // Remaining bytes: ABI-encoded bytes32
        let decoded = B256::abi_decode(&attr[4..]).expect("should decode");
        assert_eq!(decoded, head);
    }
}
