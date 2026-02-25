use std::{backtrace::Backtrace, time::Duration};

use alloy::providers::DynProvider;

use thiserror::Error;
use tracing::instrument;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{
    blockchain::{Blockchain, BlockchainEvent, RegistryEvent},
    db::{DB, IsolationLevel, PostgresDBTransaction},
    error::IndexerResult,
    rollback_executor::RollbackExecutor,
};

#[derive(Debug, Error)]
pub enum BlockchainSyncCheckError {
    #[error("no valid root found after checking up to defined max backward blocks.")]
    NoValidRootAfterBackwardBlocks(),
    #[error("this should never happen: '{0}'.")]
    ShouldNotHappen(String),
    #[error("contract call error: {source}")]
    ContractCallError {
        #[source]
        source: alloy::contract::Error,
        backtrace: String,
    },
}

impl From<alloy::contract::Error> for BlockchainSyncCheckError {
    fn from(source: alloy::contract::Error) -> Self {
        Self::ContractCallError {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

/// Periodically checks that the local in-memory Merkle root remains valid on-chain.
#[instrument(level = "info", skip_all, fields(interval_secs, max_reorg_blocks))]
pub async fn blockchain_sync_check_loop(
    interval_secs: u64,
    db: &DB,
    blockchain: &Blockchain,
    max_sync_backward_check_blocks: u64,
) -> IndexerResult<()> {
    tracing::info!(
        interval_secs,
        max_sync_backward_check_blocks,
        "Starting periodic blockchain reorg detector"
    );

    let registry = blockchain.world_id_registry();

    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        check_blocks_reorg(db).await?;

        check_latest_root(db, &registry, max_sync_backward_check_blocks).await?;
    }
}

async fn check_blocks_reorg(db: &DB) -> IndexerResult<()> {
    let mut tx = db.transaction(IsolationLevel::Serializable).await?;

    let reorg_block_hashes = tx
        .world_id_registry_events()
        .await?
        .get_reorged_block_hashes()
        .await?;

    if reorg_block_hashes.len() > 0 {
        tracing::warn!(
            ?reorg_block_hashes,
            "Found reorged blocks. Will remove events back to proper block."
        );

        let block_number = reorg_block_hashes[0].block_number;

        tx.world_id_registry_events()
            .await?
            .delete_from_block_number_inclusively(block_number)
            .await?;
    }

    Ok(())
}

async fn check_latest_root(
    db: &DB,
    registry: &WorldIdRegistryInstance<DynProvider>,
    max_sync_backward_check_blocks: u64,
) -> IndexerResult<()> {
    let mut tx = db.transaction(IsolationLevel::Serializable).await?;

    let latest_root_recorded_in_db = tx
        .world_id_registry_events()
        .await?
        .get_latest_root_recorded()
        .await?;

    let latest_root_recorded_in_db = match latest_root_recorded_in_db {
        Some(latest_root_recorded_in_db) => latest_root_recorded_in_db,
        None => {
            return {
                tx.commit().await?;
                Ok(())
            };
        }
    };

    if !is_valid_root(registry, &latest_root_recorded_in_db).await? {
        handle_reorg(
            &mut tx,
            registry,
            &latest_root_recorded_in_db,
            max_sync_backward_check_blocks,
        )
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

async fn is_valid_root(
    registry: &WorldIdRegistryInstance<DynProvider>,
    event: &BlockchainEvent<RegistryEvent>,
) -> Result<bool, BlockchainSyncCheckError> {
    let root = match &event.details {
        RegistryEvent::AccountCreated(_)
        | RegistryEvent::AccountUpdated(_)
        | RegistryEvent::AuthenticatorInserted(_)
        | RegistryEvent::AuthenticatorRemoved(_)
        | RegistryEvent::AccountRecovered(_) => {
            return Err(BlockchainSyncCheckError::ShouldNotHappen(
                "invalid registry event passed".to_string(),
            ));
        }
        RegistryEvent::RootRecorded(root_recorded_event) => root_recorded_event.root,
    };

    registry
        .isValidRoot(root)
        .call()
        .await
        .map_err(|err| err.into())
}

async fn handle_reorg<'a>(
    tx: &'a mut PostgresDBTransaction<'_>,
    registry: &WorldIdRegistryInstance<DynProvider>,
    latest_event: &BlockchainEvent<RegistryEvent>,
    max_sync_backward_check_blocks: u64,
) -> IndexerResult<()> {
    let earliest_valid_block = latest_event.block_number - max_sync_backward_check_blocks;

    let events = tx
        .world_id_registry_events()
        .await?
        .get_roots_recorded_after_block_number_inclusively(earliest_valid_block)
        .await?;
    if events.is_empty() {
        return Err(BlockchainSyncCheckError::NoValidRootAfterBackwardBlocks().into());
    }

    if !is_valid_root(registry, &events[0]).await? {
        return Err(BlockchainSyncCheckError::NoValidRootAfterBackwardBlocks().into());
    }

    let mut p = 0; // last known valid index
    let mut q = events.len() - 1;
    // Binary search for the latest valid root
    while p < q {
        let mid = (p + q + 1) / 2; // ceiling to avoid infinite loop when q == p + 1

        if is_valid_root(registry, &events[mid]).await? {
            p = mid;
        } else {
            q = mid - 1;
        }
    }
    // p is now the largest index with a valid root

    let mut rollback_executor = RollbackExecutor::new(tx);
    rollback_executor
        .rollback_to_event((events[p].block_number, events[p].log_index))
        .await?;

    return Ok(());
}
