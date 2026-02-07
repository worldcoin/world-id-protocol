//! Provides a streaming interface for WorldID registry events.
//! Backfills historic events and streams live events.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

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

static WS_BUFFER_SIZE: usize = 1024;

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
    #[error("websocket subscription closed unexpectedly")]
    WsSubscriptionClosed,
}

pub struct Blockchain {
    http_provider: DynProvider,
    ws_provider: DynProvider,
    world_id_registry: Address,
}

impl Blockchain {
    /// Creates a new [`Blockchain`] instance.
    ///
    /// # Arguments
    ///
    /// * `http_rpc_url` - The HTTP RPC URL to use for the blockchain.
    /// * `ws_rpc_url` - The WebSocket RPC URL to use for the blockchain.
    /// * `world_id_registry` - The address of the World ID registry.
    ///
    /// # Returns
    ///
    /// A new [`Blockchain`] instance.
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

        ws_provider
            .client()
            .pubsub_frontend()
            .ok_or_else(|| {
                BlockchainError::WsProvider("missing pubsub frontend on ws provider".into())
            })?
            .set_channel_size(WS_BUFFER_SIZE); // Increase buffer size to avoid losing events

        Ok(Self {
            http_provider,
            ws_provider,
            world_id_registry,
        })
    }

    /// Streams World Tree events from the blockchain.
    ///
    /// Concatenates [`Self::backfill`] with [`Self::websocket_stream`] and
    /// decodes each log into a [`BlockchainEvent<RegistryEvent>`]. The last
    /// block number seen during backfill is tracked via a shared atomic counter
    /// so that [`Self::websocket_stream`] knows where to pick up.
    ///
    /// # Arguments
    ///
    /// * `from_block` - The block number to start streaming from.
    /// * `batch_size` - The batch size to use for the backfill stage.
    ///
    /// # Returns
    ///
    /// A stream of [`BlockchainEvent<RegistryEvent>`].
    pub async fn stream_world_tree_events(
        &self,
        from_block: u64,
        batch_size: u64,
    ) -> BlockchainResult<
        impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin + '_,
    > {
        let last_block = Arc::new(AtomicU64::new(from_block.saturating_sub(1)));

        let backfill = self.backfill_stream(from_block, batch_size, last_block.clone());
        let ws = self.websocket_stream(last_block, batch_size);

        Ok(backfill
            .chain(ws)
            .map(|log_result| log_result.and_then(|log| RegistryEvent::decode(&log)))
            .boxed())
    }

    /// Starts a WebSocket log subscription and bridges the gap between the
    /// backfill stage and live events.
    ///
    /// 1. Subscribes to new logs via WebSocket (buffered to [`WS_BUFFER_SIZE`]).
    /// 2. Waits for the first live event and extracts its block number.
    /// 3. Fetches any logs that may have been missed between
    ///    `backfill_to_block + 1` and the first event's block (exclusive).
    /// 4. Returns a stream that emits, in order: the gap-fill logs, the first
    ///    live event, then the remaining live WebSocket events.
    ///
    /// All errors (including setup failures) are emitted as stream items rather
    /// than returned as an outer `Result`, consistent with how
    /// [`Self::fetch_logs_in_batches`] emits RPC errors.
    ///
    /// # Arguments
    ///
    /// * `backfill_to_block` - Shared atomic holding the last block the backfill
    ///   stage processed. Loaded lazily when the stream is first polled so the
    ///   backfill has time to update it.
    /// * `batch_size` - The batch size to use for the websocket stage.
    ///
    /// # Returns
    ///
    /// A stream of [`BlockchainResult<alloy::rpc::types::Log>`].
    fn websocket_stream(
        &self,
        backfill_to_block: Arc<AtomicU64>,
        batch_size: u64,
    ) -> impl Stream<Item = BlockchainResult<alloy::rpc::types::Log>> + Unpin + '_ {
        stream::once(async move {
            let backfill_to_block = backfill_to_block.load(Ordering::Relaxed);
            let filter = Filter::new()
                .address(self.world_id_registry)
                .event_signature(RegistryEvent::signatures());

            let sub = self
                .ws_provider
                .subscribe_logs(&filter)
                .await
                .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;

            let mut ws_stream = sub.into_stream();

            // Wait for the first live event to determine how far we need to gap-fill.
            let first_log = ws_stream
                .next()
                .await
                .ok_or(BlockchainError::WsSubscriptionClosed)?;

            let block_number = first_log
                .block_number
                .ok_or(BlockchainError::MissingBlockNumber)?;

            // Fetch any logs between the end of the backfill and the first live
            // event's block (exclusive to avoid duplicates).
            let missed_logs =
                self.fetch_logs_in_batches(backfill_to_block + 1, block_number - 1, batch_size);

            // Chain: gap-fill logs → first live event → remaining WS events
            Ok::<_, BlockchainError>(
                missed_logs
                    .chain(stream::iter(std::iter::once(Ok(first_log))))
                    .chain(ws_stream.map(Ok)),
            )
        })
        .try_flatten()
        .boxed()
    }

    /// Iteratively backfills logs from the blockchain.
    ///
    /// The idea here is that while we fetch logs, the head of the chain moves.
    /// To prevent having to buffer a lot of incoming logs from the websocket,
    /// we try to get within batch size distance from the head of the chain
    /// before switching to the websocket stage. When we reach that point, we
    /// fetch one final range covering the remaining blocks, store the last
    /// fetched block in `last_block`, and then terminate.
    ///
    /// # Arguments
    ///
    /// * `from_block` - The block number to start backfilling from.
    /// * `batch_size` - The batch size to use for the backfill stage.
    /// * `last_block` - A shared atomic counter to store the last fetched block.
    ///
    /// # Returns
    ///
    /// A stream of [`BlockchainResult<alloy::rpc::types::Log>`].
    fn backfill_stream(
        &self,
        from_block: u64,
        batch_size: u64,
        last_block: Arc<AtomicU64>,
    ) -> impl Stream<Item = BlockchainResult<alloy::rpc::types::Log>> + Unpin {
        tracing::info!(?from_block, "backfilling from block");

        stream::try_unfold((from_block, false), move |(current_from, done)| {
            let last_block = last_block.clone();
            async move {
                if done {
                    return Ok::<_, BlockchainError>(None);
                }

                let latest_block_number = self.get_block_number().await?;
                // We emit one more range here
                let is_last = latest_block_number.saturating_sub(current_from) < batch_size;
                if is_last {
                    last_block.store(latest_block_number, Ordering::Relaxed);
                }

                Ok(Some((
                    (current_from, latest_block_number),
                    (latest_block_number + 1, is_last),
                )))
            }
        })
        .map_ok(move |(from, to)| self.fetch_logs_in_batches(from, to, batch_size))
        .try_flatten()
        .boxed()
    }

    async fn get_block_number(&self) -> BlockchainResult<u64> {
        self.http_provider
            .get_block_number()
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))
    }

    /// Fetches logs in batches to avoid exceeding RPC provider's max range limits.
    ///
    /// This function chunks the block range into smaller batches and streams logs
    /// for each batch sequentially, yielding logs as they're fetched.
    ///
    /// # Arguments
    /// * `from_block` - The block number to start fetching logs from.
    /// * `to_block` - The block number to stop fetching logs at.
    /// * `batch_size` - The batch size to use for the fetch stage.
    ///
    /// # Returns
    ///
    /// A stream of [`BlockchainResult<alloy::rpc::types::Log>`].
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
