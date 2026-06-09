use std::time::Duration;

use alloy::{
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
};
use futures_util::{Stream, StreamExt, stream};
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
    /// events, then sleeps for `poll_delay` before polling again when caught up.
    /// The stream terminates after the first error.
    pub fn stream_blockchain_events(
        &self,
        from_block: u64,
        batch_size: u64,
        poll_delay: Duration,
        max_concurrent_log_requests: usize,
    ) -> impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin + '_ {
        async_stream::try_stream! {
            let mut current_from = from_block;
            let max_concurrent_log_requests = max_concurrent_log_requests.max(1);

            loop {
                let latest_block = loop {
                    let block = self.get_block_number().await?;
                    crate::metrics::set_chain_head_block(block);

                    if current_from <= block {
                        break block;
                    }

                    tokio::time::sleep(poll_delay).await;
                };

                tracing::info!(
                    "Fetching logs from block {} to {}",
                    current_from,
                    latest_block
                );

                let range_start = current_from;
                let mut total_logs = 0usize;
                let ranges = log_batch_ranges(current_from, latest_block, batch_size);

                let mut batches = stream::iter(ranges)
                    .map(|(batch_from, batch_to)| self.fetch_log_batch(batch_from, batch_to))
                    .buffered(max_concurrent_log_requests);

                while let Some(batch) = batches.next().await {
                    let logs = batch?;
                    total_logs += logs.len();

                    for log in logs {
                        yield RegistryEvent::decode(&log)?;
                    }
                }

                tracing::info!(
                    "Done fetching logs from block {} to {}: fetched {} total logs",
                    range_start,
                    latest_block,
                    total_logs,
                );

                current_from = latest_block.saturating_add(1);
            }
        }
        .boxed()
    }

    async fn fetch_log_batch(&self, from_block: u64, to_block: u64) -> BlockchainResult<Vec<Log>> {
        tracing::debug!("Fetching logs from block {} to {}", from_block, to_block);

        let batch_filter = Filter::new()
            .address(self.world_id_registry)
            .event_signature(RegistryEvent::signatures())
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.get_logs(&batch_filter).await?;

        tracing::debug!("Fetched {} logs in batch", logs.len());

        Ok(logs)
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

fn log_batch_ranges(
    from_block: u64,
    to_block: u64,
    batch_size: u64,
) -> impl Iterator<Item = (u64, u64)> {
    let batch_size = batch_size.max(1);
    let mut current_from = from_block;

    std::iter::from_fn(move || {
        if current_from > to_block {
            return None;
        }

        let current_to = (current_from + batch_size - 1).min(to_block);
        let range = (current_from, current_to);
        current_from = current_to + 1;
        Some(range)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_expected_ranges_for_hardcoded_cases() {
        let test_cases = [
            (100, 99, 64, vec![]),
            (42, 42, 64, vec![(42, 42)]),
            (0, 9, 10, vec![(0, 9)]),
            (0, 14, 10, vec![(0, 9), (10, 14)]),
            (5, 7, 1, vec![(5, 5), (6, 6), (7, 7)]),
        ];

        for (from_block, to_block, batch_size, expected_ranges) in test_cases {
            assert_eq!(
                log_batch_ranges(from_block, to_block, batch_size).collect::<Vec<_>>(),
                expected_ranges
            );
        }
    }
}
