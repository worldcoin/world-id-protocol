use std::future;

use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::{Filter, Log},
};
use futures_util::{Stream, StreamExt, stream};
use url::Url;

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

    pub async fn get_world_tree_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> anyhow::Result<Vec<Log>> {
        let filter = Filter::new()
            .address(self.world_id_registry)
            .event_signature(RegistryEvent::signatures())
            .from_block(from_block)
            .to_block(to_block);

        Ok(self.http_provider.get_logs(&filter).await?)
    }

    pub async fn stream_world_tree_events(
        &self,
        from_block: u64,
    ) -> anyhow::Result<impl Stream<Item = anyhow::Result<BlockchainEvent<RegistryEvent>>>> {
        let filter = Filter::new()
            .address(self.world_id_registry)
            .event_signature(RegistryEvent::signatures());

        let logs = self.ws_provider.subscribe_logs(&filter).await?;

        let new_events = logs.into_stream();

        let latest_block_number = self.http_provider.get_block_number().await?;

        let range_filter = filter
            .clone()
            .from_block(from_block)
            .to_block(latest_block_number);

        let backfill_events = self.http_provider.get_logs(&range_filter).await?;

        Ok(stream::iter(backfill_events)
            .chain(new_events.filter(move |v| {
                future::ready({
                    v.block_number
                        .map(|block_number| block_number > latest_block_number)
                        .unwrap_or(false)
                })
            }))
            .map(|log| RegistryEvent::decode(&log)))
    }

    pub async fn get_block_number(&self) -> anyhow::Result<u64> {
        Ok(self.http_provider.get_block_number().await?)
    }
}
