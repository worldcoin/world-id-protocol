use std::future;

use alloy::{
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
};
use futures_util::{Stream, StreamExt, stream};
use thiserror::Error;
use url::Url;

pub use crate::blockchain::events::{
    AccountCreatedEvent, AccountRecoveredEvent, AccountUpdatedEvent, AuthenticatorInsertedEvent,
    AuthenticatorRemovedEvent, BlockchainEvent, RegistryEvent, RootRecordedEvent,
};

mod events;

pub type BlockchainResult<T> = Result<T, BlockchainError>;

#[derive(Debug, Error)]
pub enum BlockchainError {
    #[error("invalid http rpc url: {0}")]
    InvalidHttpRpcUrl(#[from] url::ParseError),
    #[error("failed to connect ws provider: {0}")]
    WsProvider(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("rpc error: {0}")]
    Rpc(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("invalid log for decoding")]
    InvalidLog,
    #[error("log decode error: {0}")]
    LogDecode(#[source] alloy::sol_types::Error),
    #[error("log topics are empty")]
    EmptyTopics,
    #[error("missing block number in log topics")]
    MissingBlockNumber,
    #[error("missing transaction hash in log topics")]
    MissingTxHash,
    #[error("missing log indesx in log topics")]
    MissingLogIndex,
    #[error("unknown event signature: {0:?}")]
    UnknownEventSignature(FixedBytes<32>),
}

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
    ) -> BlockchainResult<Self> {
        let http_url = Url::parse(http_rpc_url)?;
        let http_provider = DynProvider::new(ProviderBuilder::new().connect_http(http_url));

        let ws_provider = DynProvider::new(
            ProviderBuilder::new()
                .connect_ws(WsConnect::new(ws_rpc_url))
                .await
                .map_err(|err| BlockchainError::WsProvider(Box::new(err)))?,
        );

        Ok(Self {
            http_provider,
            ws_provider,
            world_id_registry,
        })
    }

    /// Streams World Tree events from the blockchain.
    ///
    /// This function ensures that no events are missed by combining historical
    /// events (from `from_block` to the latest block) with new events from a
    /// WebSocket subscription. The WebSocket subscription only returns new logs,
    /// so we backfill historical data. Additionally, it filters out duplicates
    /// by only including new events that occur after the latest block number
    /// at the time of the query. It is crucial to first create a subscription
    /// and then check for last block number to not miss any logs between the
    /// call for last block number and subscription creation.
    pub async fn stream_world_tree_events(
        &self,
        from_block: u64,
    ) -> BlockchainResult<impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>>>
    {
        let filter = Filter::new()
            .address(self.world_id_registry)
            .event_signature(RegistryEvent::signatures());

        let logs = self
            .ws_provider
            .subscribe_logs(&filter)
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;

        let new_events = logs.into_stream();

        let latest_block_number = self
            .http_provider
            .get_block_number()
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;

        let range_filter = filter
            .clone()
            .from_block(from_block)
            .to_block(latest_block_number);

        let backfill_events = self
            .http_provider
            .get_logs(&range_filter)
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;

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

    /// Fetch all historical events from `from_block` to the current latest block.
    /// Returns the logs and the block number they were fetched up to (inclusive).
    pub async fn get_backfill_events(
        &self,
        from_block: u64,
    ) -> BlockchainResult<(Vec<alloy::rpc::types::Log>, u64)> {
        let filter = Filter::new()
            .address(self.world_id_registry)
            .event_signature(RegistryEvent::signatures());

        let latest_block_number = self
            .http_provider
            .get_block_number()
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;

        if from_block > latest_block_number {
            return Ok((vec![], latest_block_number));
        }

        let range_filter = filter
            .from_block(from_block)
            .to_block(latest_block_number);

        let logs = self
            .http_provider
            .get_logs(&range_filter)
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;

        Ok((logs, latest_block_number))
    }

    pub async fn get_block_number(&self) -> BlockchainResult<u64> {
        self.http_provider
            .get_block_number()
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))
    }
}
