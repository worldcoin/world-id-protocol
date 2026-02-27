use std::{future::Future, pin::Pin};

use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::DynProvider;
use eyre::Result;

use crate::proof::ChainCommitment;
use crate::proof::permissioned::build_permissioned_proof_attributes;
use crate::relay::send_relay_tx;

use super::Satellite;

/// A satellite that uses the permissioned (owner-attested) gateway.
///
/// The simplest proof path: the relay transaction must be sent from the gateway owner's
/// wallet. The proof attribute is just the chain head hash.
pub struct PermissionedSatellite {
    name: String,
    chain_id: u64,
    gateway_address: Address,
    bridge_address: Address,
    /// The chain ID of the anchor (source) chain, used for ERC-7930 address encoding.
    anchor_chain_id: u64,
    provider: DynProvider,
}

impl PermissionedSatellite {
    /// Creates a new permissioned satellite.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for logging.
    /// * `chain_id` - The chain ID of this destination chain.
    /// * `gateway` - The permissioned gateway contract address.
    /// * `bridge` - The satellite bridge contract address.
    /// * `anchor_chain_id` - The chain ID of World Chain (source).
    /// * `provider` - A provider with signing capability for this destination chain.
    pub fn new(
        name: impl Into<String>,
        chain_id: u64,
        gateway: Address,
        bridge: Address,
        anchor_chain_id: u64,
        provider: DynProvider,
    ) -> Self {
        Self {
            name: name.into(),
            chain_id,
            gateway_address: gateway,
            bridge_address: bridge,
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
            let (attribute, payload) = build_permissioned_proof_attributes(commitment);
            Ok((attribute, payload))
        })
    }

    fn relay<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>> {
        Box::pin(async move {
            let (attribute, payload) = build_permissioned_proof_attributes(commitment);
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
