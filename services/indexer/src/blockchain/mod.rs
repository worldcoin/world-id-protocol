use std::future;

use alloy::{
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
};
use futures_util::{Stream, StreamExt, TryStreamExt, stream};
use thiserror::Error;
use url::Url;

pub use crate::blockchain::events::{BlockchainEvent, RegistryEvent};

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
    ///
    /// The `backfill_batch_size` parameter controls how many blocks are queried
    /// at once during the backfill process. This is necessary because RPC providers
    /// typically have a maximum range limit per query.
    pub async fn stream_world_tree_events(
        &self,
        from_block: u64,
        backfill_batch_size: u64,
    ) -> BlockchainResult<
        impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin,
    > {
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

        let backfill_stream =
            self.fetch_logs_in_batches(from_block, latest_block_number, backfill_batch_size);

        Ok(backfill_stream
            .chain(
                new_events
                    .filter(move |v| {
                        future::ready({
                            v.block_number
                                .map(|block_number| block_number > latest_block_number)
                                .unwrap_or(false)
                        })
                    })
                    .map(Ok),
            )
            .map(|log_result| log_result.and_then(|log| RegistryEvent::decode(&log)))
            .boxed())
    }

    pub async fn backfill(
        &self,
        from_block: u64,
        batch_size: u64,
    ) -> impl Stream<Item = BlockchainResult<alloy::rpc::types::Log>> + Unpin {
        tracing::info!(?from_block, "backfilling from block");

        stream::try_unfold(from_block, move |current_from| async move {
            let latest_block_number = self.get_block_number().await?;

            if latest_block_number.saturating_sub(current_from) < batch_size {
                return Ok::<_, BlockchainError>(None);
            }

            Ok(Some((
                (current_from, latest_block_number),
                latest_block_number + 1,
            )))
        })
        .map_ok(move |(from, to)| self.fetch_logs_in_batches(from, to, batch_size))
        .try_flatten()
        .boxed()
    }

    pub async fn get_block_number(&self) -> BlockchainResult<u64> {
        self.http_provider
            .get_block_number()
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))
    }

    /// Fetches logs in batches to avoid exceeding RPC provider's max range limits.
    ///
    /// This function chunks the block range into smaller batches and streams logs
    /// for each batch sequentially, yielding logs as they're fetched.
    fn fetch_logs_in_batches(
        &self,
        from_block: u64,
        to_block: u64,
        batch_size: u64,
    ) -> impl Stream<Item = BlockchainResult<alloy::rpc::types::Log>> + Unpin {
        let http_provider = self.http_provider.clone();
        let world_id_registry = self.world_id_registry;

        let initial_state = (
            from_block, // start block
            0usize,     // total logs fetched; we keep this only for logging
        );

        stream::try_unfold(initial_state, move |(current_from, total_logs)| {
            let http_provider = http_provider.clone();

            async move {
                if current_from > to_block {
                    tracing::info!(
                        "Backfill step complete: fetched {} total logs from block {} to {}",
                        total_logs,
                        from_block,
                        to_block
                    );
                    return Ok::<_, BlockchainError>(None);
                }

                let current_to = std::cmp::min(current_from + batch_size - 1, to_block);

                tracing::debug!(
                    "Fetching logs from block {} to {}",
                    current_from,
                    current_to
                );

                let batch_filter = Filter::new()
                    .address(world_id_registry)
                    .event_signature(RegistryEvent::signatures())
                    .from_block(current_from)
                    .to_block(current_to);

                let logs = http_provider
                    .get_logs(&batch_filter)
                    .await
                    .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;

                tracing::debug!("Fetched {} logs in batch", logs.len());

                let new_total = total_logs + logs.len();
                let next_from = current_to + 1;

                Ok(Some((
                    stream::iter(logs.into_iter().map(Ok)),
                    (next_from, new_total),
                )))
            }
        })
        .try_flatten()
        .boxed()
    }
}
