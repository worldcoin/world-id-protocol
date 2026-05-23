use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::{
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
};
use futures_util::{Stream, StreamExt, TryStreamExt, stream};
use thiserror::Error;

pub use crate::blockchain::events::{
    AccountCreatedEvent, AccountRecoveredEvent, AccountUpdatedEvent, AuthenticatorInsertedEvent,
    AuthenticatorRemovedEvent, BlockchainEvent, RegistryEvent, RootRecordedEvent,
};

mod events;

pub type BlockchainResult<T> = Result<T, BlockchainError>;

#[derive(Debug, Error)]
pub enum BlockchainError {
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
}

pub struct Blockchain {
    http_provider: DynProvider,
    world_id_registry: Address,
}

impl Blockchain {
    /// Creates a new [`Blockchain`] instance used to stream events from the blockchain.
    ///
    /// # Arguments
    ///
    /// * `http_provider` - A pre-built HTTP provider (e.g. from [`ProviderArgs::http()`]).
    /// * `world_id_registry` - The address of the World ID registry.
    pub fn new(http_provider: DynProvider, world_id_registry: Address) -> Self {
        Self {
            http_provider,
            world_id_registry,
        }
    }

    /// Returns a [`WorldIdRegistryInstance`] bound to the HTTP provider.
    pub fn world_id_registry(
        &self,
    ) -> world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance<DynProvider> {
        world_id_registries::world_id::WorldIdRegistry::new(
            self.world_id_registry,
            self.http_provider.clone(),
        )
    }

    /// Streams registry events via periodic HTTP polling.
    ///
    /// Fetches logs from `from_block` up to the current chain head, emits decoded
    /// events, then sleeps for `poll_interval` before polling again. The stream
    /// terminates after the first error.
    pub fn pull_events(
        &self,
        from_block: u64,
        batch_size: u64,
        poll_interval: Duration,
    ) -> impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin + '_ {
        stream::unfold(
            (from_block, VecDeque::new()),
            move |(mut current_from, mut pending)| async move {
                loop {
                    if let Some(event) = pending.pop_front() {
                        return Some((event, (current_from, pending)));
                    }

                    let latest_block = match self.get_block_number().await {
                        Ok(block) => block,
                        Err(err) => return Some((Err(err), (current_from, pending))),
                    };
                    crate::metrics::set_chain_head_block(latest_block);

                    if current_from > latest_block {
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }

                    let events: Vec<BlockchainResult<BlockchainEvent<RegistryEvent>>> = self
                        .fetch_logs_in_batches(current_from, latest_block, batch_size)
                        .map(|result| result.and_then(|log| RegistryEvent::decode(&log)))
                        .collect()
                        .await;

                    pending = events.into();
                    current_from = latest_block.saturating_add(1);
                }
            },
        )
        .boxed()
        .stop_after_first_error()
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

    /// Iteratively backfills logs from the blockchain up to the current head.
    ///
    /// While fetching, the chain head may advance. The stream chases the head
    /// until within `batch_size` blocks, then fetches one final range and stops.
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
                crate::metrics::set_chain_head_block(latest_block_number);

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
