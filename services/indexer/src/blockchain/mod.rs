use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use alloy::{
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    pubsub::Subscription,
    rpc::types::{Filter, Log},
};
use futures_util::{Stream, StreamExt, TryStreamExt, stream};
use thiserror::Error;

pub use crate::blockchain::events::{
    AccountCreatedEvent, AccountRecoveredEvent, AccountUpdatedEvent, AuthenticatorInsertedEvent,
    AuthenticatorRemovedEvent, BlockchainEvent, RegistryEvent, RootRecordedEvent,
};

mod events;

static WS_BUFFER_SIZE: usize = 1024;

pub type BlockchainResult<T> = Result<T, BlockchainError>;

#[derive(Debug, Error)]
pub enum BlockchainError {
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
    #[error("missing block hash in log topics")]
    MissingBlockHash,
    #[error("missing transaction hash in log topics")]
    MissingTxHash,
    #[error("missing log index in log topics")]
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
    /// Creates a new [`Blockchain`] instance used to stream events from the blockchain.
    /// Note: We consider any errors as fatal and stop the stream.
    ///
    /// # Arguments
    ///
    /// * `http_provider` - A pre-built HTTP provider (e.g. from [`ProviderArgs::http()`]).
    /// * `ws_rpc_url` - The WebSocket RPC URL to use for the blockchain.
    /// * `world_id_registry` - The address of the World ID registry.
    ///
    /// # Returns
    ///
    /// A new [`Blockchain`] instance.
    pub async fn new(
        http_provider: DynProvider,
        ws_rpc_url: &str,
        world_id_registry: Address,
    ) -> BlockchainResult<Self> {
        // Disable internal WS reconnect so drops surface immediately as errors.
        let ws_connect = WsConnect::new(ws_rpc_url).with_max_retries(0);
        let ws_provider = DynProvider::new(
            ProviderBuilder::new()
                .connect_ws(ws_connect)
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

    /// Returns a [`WorldIdRegistryInstance`] bound to the HTTP provider.
    pub fn world_id_registry(
        &self,
    ) -> world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance<DynProvider>
    {
        world_id_core::world_id_registry::WorldIdRegistry::new(
            self.world_id_registry,
            self.http_provider.clone(),
        )
    }

    /// Streams World Tree events from the blockchain.
    ///
    /// Concatenates [`Self::backfill_stream`] with [`Self::websocket_stream`] and
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
    /// A stream of [`BlockchainEvent<RegistryEvent>`]. The stream terminates
    /// after the first error.
    pub fn backfill_and_stream_events(
        &self,
        from_block: u64,
        batch_size: u64,
    ) -> impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin + '_ {
        let last_block = Arc::new(AtomicU64::new(from_block.saturating_sub(1)));

        let backfill = self.backfill_stream(from_block, batch_size, last_block.clone());
        let ws = self.websocket_stream(last_block, batch_size);

        backfill.chain(ws).stop_after_first_error()
    }

    /// Returns a decoded backfill event stream and a shared atomic holding the
    /// last block number that was fetched. The atomic is updated during
    /// streaming and should be read after the stream is fully consumed.
    ///
    /// Each raw log is decoded into a [`BlockchainEvent<RegistryEvent>`];
    /// decode failures are surfaced as [`BlockchainError`] stream items.
    ///
    /// # Arguments
    ///
    /// * `from_block` - The block number to start backfilling from.
    /// * `batch_size` - The batch size to use for the backfill stage.
    ///
    /// # Returns
    ///
    /// A tuple of (stream, last_block_atomic). The stream terminates after
    /// the first error.
    pub fn backfill_events(
        &self,
        from_block: u64,
        batch_size: u64,
    ) -> (
        impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin,
        Arc<AtomicU64>,
    ) {
        let last_block = Arc::new(AtomicU64::new(from_block.saturating_sub(1)));
        let stream = self
            .backfill_stream(from_block, batch_size, last_block.clone())
            .stop_after_first_error();
        (stream, last_block)
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
    /// A stream of decoded [`BlockchainResult<BlockchainEvent<RegistryEvent>>`].
    /// Returns [`BlockchainError::WsSubscriptionClosed`] and stops in case the websocket is dropped.
    fn websocket_stream(
        &self,
        backfill_to_block: Arc<AtomicU64>,
        batch_size: u64,
    ) -> impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin {
        stream::once(async move {
            let backfill_to_block = backfill_to_block.load(Ordering::Relaxed);
            let filter = Filter::new()
                .address(self.world_id_registry)
                .event_signature(RegistryEvent::signatures());

            let sub = self.subscribe_logs(&filter).await?;

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
            // Edge case: Use `saturating_sub` to avoid underflow when `block_number` is 0.
            let missed_logs = self
                .fetch_logs_in_batches(
                    backfill_to_block.saturating_add(1),
                    block_number.saturating_sub(1),
                    batch_size,
                )
                .map(|r| r.and_then(|log| RegistryEvent::decode(&log)));

            // Chain: gap-fill logs → first live event → remaining WS events
            let first_decoded = RegistryEvent::decode(&first_log);
            Ok::<_, BlockchainError>(
                missed_logs
                    .chain(stream::iter(std::iter::once(first_decoded)))
                    .chain(ws_stream.map(|log| RegistryEvent::decode(&log)))
                    // If the websocket subscription is closed, we return an error.
                    .chain(stream::once(async {
                        Err(BlockchainError::WsSubscriptionClosed)
                    })),
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
    /// A stream of decoded [`BlockchainResult<BlockchainEvent<RegistryEvent>>`].
    fn backfill_stream(
        &self,
        from_block: u64,
        batch_size: u64,
        last_block: Arc<AtomicU64>,
    ) -> impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin {
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
        .map_ok(move |(from, to)| {
            self.fetch_logs_in_batches(from, to, batch_size)
                .map(|r| r.and_then(|log| RegistryEvent::decode(&log)))
        })
        .try_flatten()
        .boxed()
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
    /// A stream of [`BlockchainResult<alloy::rpc::types::Log>`]. The stream
    /// terminates after the first error.
    fn fetch_logs_in_batches(
        &self,
        from_block: u64,
        to_block: u64,
        batch_size: u64,
    ) -> impl Stream<Item = BlockchainResult<Log>> + Unpin {
        let initial_state = (
            from_block, // start block
            0usize,     // total logs fetched; we keep this only for logging
        );

        stream::try_unfold(
            initial_state,
            move |(current_from, total_logs)| async move {
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
                    .address(self.world_id_registry)
                    .event_signature(RegistryEvent::signatures())
                    .from_block(current_from)
                    .to_block(current_to);

                let logs = self.get_logs(&batch_filter).await?;

                tracing::debug!("Fetched {} logs in batch", logs.len());

                let new_total = total_logs + logs.len();
                let next_from = current_to + 1;

                Ok(Some((
                    stream::iter(logs.into_iter().map(Ok)),
                    (next_from, new_total),
                )))
            },
        )
        .try_flatten()
        .boxed()
    }

    async fn get_block_number(&self) -> BlockchainResult<u64> {
        self.http_provider
            .get_block_number()
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))
    }

    async fn get_logs(&self, filter: &Filter) -> BlockchainResult<Vec<Log>> {
        self.http_provider
            .get_logs(filter)
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))
    }

    async fn subscribe_logs(&self, filter: &Filter) -> BlockchainResult<Subscription<Log>> {
        self.ws_provider
            .subscribe_logs(filter)
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))
    }
}

/// Small extension trait to stop a stream after the first error.
pub trait StopAfterFirstErrorExt<T, E>: Stream<Item = Result<T, E>> + Sized {
    fn stop_after_first_error(self) -> impl Stream<Item = Result<T, E>> + Unpin;
}

impl<S, T, E> StopAfterFirstErrorExt<T, E> for S
where
    S: Stream<Item = Result<T, E>> + Sized + Unpin,
{
    fn stop_after_first_error(self) -> impl Stream<Item = Result<T, E>> + Unpin {
        self.scan(false, |seen_err, item| {
            if *seen_err {
                return std::future::ready(None);
            }

            if item.is_err() {
                *seen_err = true;
            }

            std::future::ready(Some(item))
        })
    }
}
