use std::{future::Future, pin::Pin, sync::Arc};

use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, Bytes, address},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use eyre::Result;
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionRequest};
use tracing::info;

use crate::{
    bindings::{IGateway, IWorldIDSatellite::IWorldIDSatelliteInstance},
    primitives::ChainCommitment,
    relay::encode_evm_v1_address,
    satellite::Satellite,
};

use super::build_chain_head_attribute;

/// USDC.e (TIP-20) fee token on Tempo.
const FEE_TOKEN: Address = address!("0x20c000000000000000000000b9537d11c60e8b50");

/// A permissioned satellite targeting a Tempo blockchain destination.
///
/// Uses `TempoNetwork` provider with 2D random nonces and pays gas fees
/// in the AlphaUSD TIP-20 token. Reads (e.g. querying the satellite contract)
/// go through a standard Ethereum-typed provider, while relay transactions
/// are sent through the Tempo-typed provider.
pub struct TempoSatellite<P> {
    name: String,
    chain_id: u64,
    /// Standard provider for contract reads (sol! bindings require Ethereum network).
    satellite_instance: IWorldIDSatelliteInstance<Arc<DynProvider>>,
    satellite_address: Address,
    gateway_address: Address,
    anchor_chain_id: u64,
    /// Tempo-typed provider for sending transactions.
    provider: P,
}

impl<P: Provider<TempoNetwork> + Send + Sync + Clone + 'static> TempoSatellite<P> {
    pub fn new(
        name: impl Into<String>,
        anchor_chain_id: u64,
        gateway_address: Address,
        satellite_address: Address,
        destination_chain_id: u64,
        read_provider: Arc<DynProvider>,
        provider: P,
    ) -> Self {
        Self {
            name: name.into(),
            chain_id: destination_chain_id,
            satellite_instance: IWorldIDSatelliteInstance::new(satellite_address, read_provider),
            satellite_address,
            gateway_address,
            anchor_chain_id,
            provider,
        }
    }
}

impl<P: Provider<TempoNetwork> + Send + Sync + Clone + 'static> Satellite for TempoSatellite<P> {
    fn name(&self) -> &str {
        &self.name
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn remote_chain_head<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>> {
        Box::pin(async move {
            let result = self.satellite_instance.KECCAK_CHAIN().call().await?;
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

            let recipient = encode_evm_v1_address(self.anchor_chain_id, self.satellite_address);
            let attributes = vec![attribute];

            let call = IGateway::sendMessageCall {
                recipient: recipient.into(),
                payload,
                attributes,
            };

            let inner = TransactionRequest::default()
                .to(self.gateway_address)
                .input(call.abi_encode().into());

            let tx = TempoTransactionRequest {
                inner,
                fee_token: Some(FEE_TOKEN),
                ..Default::default()
            };

            let pending = self.provider.send_transaction(tx).await?;
            let tx_hash = *pending.tx_hash();

            info!(%tx_hash, gateway = %self.gateway_address, "tempo relay transaction sent");

            let receipt = pending.get_receipt().await?;

            if !receipt.status() {
                eyre::bail!("tempo relay transaction reverted: {tx_hash}");
            }

            info!(%tx_hash, "tempo relay transaction confirmed");
            Ok(tx_hash)
        })
    }
}
