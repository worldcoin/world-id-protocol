use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use futures_util::{Stream, StreamExt};
use url::Url;
use world_id_core::world_id_registry::WorldIdRegistry;

pub use crate::blockchain::events::{BlockchainEvent, RegistryEvent};

mod events;

pub struct Blockchain {
    http_provider: DynProvider,
    ws_provider: DynProvider,
    world_id_registry: Address,
}

impl Blockchain {
    pub async fn new(
        http_rpc_url: &str,
        ws_rpc_url: &str,
        world_id_registry: Address,
    ) -> anyhow::Result<Self> {
        let http_provider =
            DynProvider::new(ProviderBuilder::new().connect_http(Url::parse(http_rpc_url)?));

        let ws_provider = DynProvider::new(
            ProviderBuilder::new()
                .connect_ws(WsConnect::new(ws_rpc_url))
                .await?,
        );

        Ok(Self {
            http_provider,
            ws_provider,
            world_id_registry,
        })
    }

    pub async fn get_world_id_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> anyhow::Result<Vec<BlockchainEvent<RegistryEvent>>> {
        let event_signatures = vec![
            WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
            WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
            WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
        ];

        let filter = Filter::new()
            .address(self.world_id_registry)
            .event_signature(event_signatures)
            .from_block(from_block)
            .to_block(to_block);

        self.http_provider
            .get_logs(&filter)
            .await?
            .iter()
            .map(events::decode_registry_event)
            .collect()
    }

    pub async fn stream_world_id_events(
        &self,
        from_block: u64,
    ) -> anyhow::Result<impl Stream<Item = anyhow::Result<BlockchainEvent<RegistryEvent>>>> {
        let event_signatures = vec![
            WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
            WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
            WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
        ];

        let filter = Filter::new()
            .address(self.world_id_registry)
            .event_signature(event_signatures)
            .from_block(from_block);

        let logs = self.ws_provider.subscribe_logs(&filter).await?;

        Ok(logs
            .into_stream()
            .map(|log| events::decode_registry_event(&log)))
    }

    pub async fn get_block_number(&self) -> anyhow::Result<u64> {
        Ok(self.http_provider.get_block_number().await?)
    }
}
