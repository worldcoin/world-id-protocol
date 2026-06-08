use std::time::Duration;

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
        stream::unfold(from_block, move |current_from| async move {
            // Poll the chain head until there is a non-empty range to fetch.
            let latest_block = loop {
                match self.get_block_number().await {
                    Ok(block) => {
                        crate::metrics::set_chain_head_block(block);
                        if current_from <= block {
                            break block;
                        }
                        tokio::time::sleep(poll_interval).await;
                    }
                    // Surface the head-poll error as a terminal stream item.
                    Err(err) => {
                        let errored = stream::once(async move { Err(err) }).left_stream();
                        return Some((errored, current_from));
                    }
                }
            };

            // Lazily stream the range batch-by-batch; `flatten` emits one event
            // at a time and only pulls the next batch once the current one drains.
            let batch = self
                .fetch_logs_in_batches(current_from, latest_block, batch_size)
                .map(|result| result.and_then(|log| RegistryEvent::decode(&log)))
                .right_stream();

            Some((batch, latest_block.saturating_add(1)))
        })
        .flatten()
        .boxed()
        .stop_after_first_error()
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
