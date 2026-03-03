use std::{future::Future, pin::Pin};

use alloy::{
    primitives::{Address, B256, Bytes},
    providers::DynProvider,
};
use eyre::Result;
use url::Url;

use crate::{
    proof::{ChainCommitment, light_client::build_light_client_proof_attributes},
    relay::send_relay_tx,
};

use super::Satellite;

pub struct LightClientSatellite {
    name: String,
    chain_id: u64,
    gateway_address: Address,
    bridge_address: Address,
    anchor_chain_id: u64,
    dest_provider: DynProvider,
    l1_provider: DynProvider,
    l1_bridge_address: Address,
    helios_prover_url: Url,
}

impl LightClientSatellite {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        chain_id: u64,
        gateway: Address,
        bridge: Address,
        anchor_chain_id: u64,
        dest_provider: DynProvider,
        l1_provider: DynProvider,
        l1_bridge_address: Address,
        helios_prover_url: Url,
    ) -> Self {
        Self {
            name: name.into(),
            chain_id,
            gateway_address: gateway,
            bridge_address: bridge,
            anchor_chain_id,
            dest_provider,
            l1_provider,
            l1_bridge_address,
            helios_prover_url,
        }
    }
}

impl Satellite for LightClientSatellite {
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
            build_light_client_proof_attributes(
                &self.l1_provider,
                &self.dest_provider,
                self.l1_bridge_address,
                self.gateway_address,
                &self.helios_prover_url,
                commitment,
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
                &self.dest_provider,
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
