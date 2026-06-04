use std::{sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
};
use backon::{ExponentialBuilder, Retryable};
use futures_util::{Stream, StreamExt, TryStreamExt, stream};
use thiserror::Error;
use tokio::{sync::Semaphore, task::JoinSet};

pub use crate::blockchain::events::{
    AccountCreatedEvent, AccountRecoveredEvent, AccountUpdatedEvent, AuthenticatorInsertedEvent,
    AuthenticatorRemovedEvent, BlockchainEvent, RegistryEvent, RegistryEventExt, RootRecordedEvent,
};

mod events;

/// Maximum number of concurrent `eth_getLogs` requests in flight while
/// fetching a block range. Bounds RPC fan-out across the whole program.
const SEMAPHORE_PERMIT: usize = 16;

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
    #[error(transparent)]
    AlloySolTypes(#[from] alloy::sol_types::Error),
}

pub struct Blockchain {
    http_provider: DynProvider,
    world_id_registry: Address,
}

impl Blockchain {
    /// Creates a new [`Blockchain`] instance used to poll events from the blockchain.
    /// Note: We consider any errors as fatal and stop the stream.
    ///
    /// # Arguments
    ///
    /// * `http_provider` - A pre-built HTTP provider (e.g. from [`ProviderArgs::http()`]).
    /// * `world_id_registry` - The address of the World ID registry.
    ///
    /// # Returns
    ///
    /// A new [`Blockchain`] instance.
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

    /// Polls the blockchain for registry events over HTTP and decodes each log
    /// into a [`BlockchainEvent<RegistryEvent>`].
    ///
    /// Only logs at or below the *confirmed* head (`chain_head - confirmations`)
    /// are emitted. This keeps the indexer behind the unsafe head so that
    /// short-lived reorgs of preconfirmed blocks never reach the committer,
    /// which is the failure mode the previous WebSocket subscription suffered
    /// from. A single HTTP provider determines both the head and the logs, so
    /// there is no cross-provider view mismatch.
    ///
    /// The first poll fetches the full backlog (`from_block ..= confirmed_head`)
    /// in one step, internally chunked by [`Self::fetch_logs_in_batches`]. Each
    /// subsequent poll waits `poll_interval`, then emits any newly confirmed
    /// logs.
    ///
    /// # Arguments
    ///
    /// * `from_block` - The block number to start polling from.
    /// * `batch_size` - The batch size to use when fetching log ranges.
    /// * `confirmations` - Number of blocks to stay behind the chain head.
    /// * `poll_interval` - How long to wait between polls once caught up.
    ///
    /// # Returns
    ///
    /// A stream of decoded [`BlockchainEvent<RegistryEvent>`]. The stream
    /// terminates after the first error (e.g. an RPC failure).
    pub fn poll_events(
        &self,
        from_block: u64,
        batch_size: u64,
        confirmations: u64,
        poll_interval: Duration,
    ) -> impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin + '_ {
        tracing::info!(?from_block, confirmations, "polling from block");

        stream::try_unfold(
            (from_block, true),
            move |(current_from, first)| async move {
                // Wait between poll cycles once we have caught up. The first cycle
                // runs immediately so the initial backfill isn't delayed.
                if !first {
                    tokio::time::sleep(poll_interval).await;
                }

                loop {
                    let chain_head = self.get_block_number().await?;
                    crate::metrics::set_chain_head_block(chain_head);

                    let confirmed_head = chain_head.saturating_sub(confirmations);
                    if confirmed_head >= current_from {
                        return Ok::<_, BlockchainError>(Some((
                            (current_from, confirmed_head),
                            (confirmed_head + 1, false),
                        )));
                    }

                    // No newly confirmed blocks yet; wait and re-check.
                    tokio::time::sleep(poll_interval).await;
                }
            },
        )
        .map_ok(move |(from, to)| {
            self.fetch_logs_in_batches(from, to, batch_size)
                .map(|r| r.and_then(|log| RegistryEvent::decode(&log)))
        })
        .try_flatten()
        .boxed()
    }

    /// Fetches logs across a block range, concurrently and in batches.
    ///
    /// The range is processed in bounded windows of `SEMAPHORE_PERMIT *
    /// batch_size` blocks. Each window fans out one task per `batch_size` chunk
    /// (capped at [`SEMAPHORE_PERMIT`] concurrent requests), then emits the
    /// window's logs in block order before moving to the next window. Windowing
    /// keeps memory and task count bounded even for a large initial backfill.
    ///
    /// # Arguments
    /// * `from_block` - The block number to start fetching logs from.
    /// * `to_block` - The block number to stop fetching logs at.
    /// * `batch_size` - The number of blocks per `eth_getLogs` request.
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
    ) -> impl Stream<Item = BlockchainResult<Log>> + Unpin + '_ {
        let window = SEMAPHORE_PERMIT as u64 * batch_size;

        stream::try_unfold(from_block, move |current_from| async move {
            if current_from > to_block {
                return Ok::<_, BlockchainError>(None);
            }

            let window_end = current_from.saturating_add(window - 1).min(to_block);

            let logs = self
                .fetch_window_parallel(current_from, window_end, batch_size)
                .await?;

            tracing::debug!(
                from = current_from,
                to = window_end,
                count = logs.len(),
                "fetched log window"
            );

            Ok(Some((
                stream::iter(logs.into_iter().map(Ok)),
                window_end + 1,
            )))
        })
        .try_flatten()
        .boxed()
    }

    /// Fetches all logs in `[from_block, to_block]` concurrently, one task per
    /// `batch_size` chunk, bounded by a [`SEMAPHORE_PERMIT`]-permit semaphore.
    /// Each task retries transient RPC failures with exponential backoff.
    ///
    /// Tasks complete out of order, so the collected batches are re-sorted by
    /// their chunk index to restore block order before being flattened.
    async fn fetch_window_parallel(
        &self,
        from_block: u64,
        to_block: u64,
        batch_size: u64,
    ) -> BlockchainResult<Vec<Log>> {
        // Build the ordered batch ranges covering the window.
        let mut ranges = Vec::new();
        let mut cursor = from_block;
        while cursor <= to_block {
            let end = cursor.saturating_add(batch_size - 1).min(to_block);
            ranges.push((cursor, end));
            if end == u64::MAX {
                break;
            }
            cursor = end + 1;
        }

        let semaphore = Arc::new(Semaphore::new(SEMAPHORE_PERMIT));
        let mut join_set: JoinSet<BlockchainResult<(usize, Vec<Log>)>> = JoinSet::new();

        for (idx, (start, end)) in ranges.into_iter().enumerate() {
            let provider = self.http_provider.clone();
            let registry = self.world_id_registry;
            let semaphore = semaphore.clone();

            join_set.spawn(async move {
                // Cap the number of concurrent in-flight requests.
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|e| BlockchainError::Rpc(Box::new(e)))?;

                let filter = Filter::new()
                    .address(registry)
                    .event_signature(RegistryEvent::signatures())
                    .from_block(start)
                    .to_block(end);

                let logs = (|| async { provider.get_logs(&filter).await })
                    .retry(ExponentialBuilder::default().with_jitter())
                    .await
                    .map_err(|e| BlockchainError::Rpc(Box::new(e)))?;

                Ok((idx, logs))
            });
        }

        // Collect all batches; fail fast on the first error (dropping the
        // JoinSet aborts any still-running tasks).
        let mut batches: Vec<(usize, Vec<Log>)> = Vec::new();
        while let Some(joined) = join_set.join_next().await {
            let batch = joined.map_err(|e| BlockchainError::Rpc(Box::new(e)))??;
            batches.push(batch);
        }

        batches.sort_by_key(|(idx, _)| *idx);
        Ok(batches.into_iter().flat_map(|(_, logs)| logs).collect())
    }

    async fn get_block_number(&self) -> BlockchainResult<u64> {
        self.http_provider
            .get_block_number()
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))
    }

    /// Current chain head (tip) block number.
    pub(crate) async fn current_block(&self) -> BlockchainResult<u64> {
        self.get_block_number().await
    }

    /// Fetch and decode all registry events in `[from_block, to_block]`,
    /// concurrently and in order. The caller is responsible for keeping the
    /// range bounded (e.g. one poll window) to bound memory and task count.
    pub(crate) async fn fetch_events(
        &self,
        from_block: u64,
        to_block: u64,
        batch_size: u64,
    ) -> BlockchainResult<Vec<BlockchainEvent<RegistryEvent>>> {
        let logs = self
            .fetch_window_parallel(from_block, to_block, batch_size)
            .await?;
        logs.iter().map(RegistryEvent::decode).collect()
    }

    /// Fetch the canonical block hash for `number`, or `None` if the block is
    /// not (yet) present on the canonical chain. Used to detect reorgs of
    /// already-ingested, not-yet-confirmed blocks.
    pub(crate) async fn canonical_block_hash(
        &self,
        number: u64,
    ) -> BlockchainResult<Option<alloy::primitives::U256>> {
        let block = self
            .http_provider
            .get_block_by_number(number.into())
            .await
            .map_err(|err| BlockchainError::Rpc(Box::new(err)))?;
        Ok(block.map(|b| b.header.hash.into()))
    }
}
