use std::{backtrace::Backtrace, time::Duration};

use alloy::{primitives::U256, providers::DynProvider};

use thiserror::Error;
use tracing::instrument;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{
    blockchain::{Blockchain, BlockchainError, BlockchainEvent, RootRecordedEvent},
    db::{DB, IsolationLevel, PostgresDBTransaction, WorldIdRegistryEventId},
    error::IndexerResult,
    rollback_executor::RollbackExecutor,
};

#[derive(Debug, Error)]
pub enum BlockchainSyncCheckError {
    #[error("reorg beyond configured max backward blocks detected.")]
    NoValidRootAfterBackwardBlocks(),
    #[error("this should never happen: '{0}'.")]
    ShouldNotHappen(String),
    #[error("contract call error: {source}")]
    ContractCallError {
        #[source]
        source: alloy::contract::Error,
        backtrace: String,
    },
    #[error("blockchain error: {source}")]
    BlockchainError {
        #[source]
        source: BlockchainError,
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

impl From<BlockchainError> for BlockchainSyncCheckError {
    fn from(source: BlockchainError) -> Self {
        Self::BlockchainError {
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

        check_latest_root(db, blockchain, &registry, max_sync_backward_check_blocks).await?;
    }
}

async fn check_blocks_reorg(db: &DB) -> IndexerResult<()> {
    let mut tx = db.transaction(IsolationLevel::Serializable).await?;

    let reorg_block_hashes = tx
        .world_id_registry_events()
        .await?
        .get_blocks_with_conflicting_hashes()
        .await?;

    if !reorg_block_hashes.is_empty() {
        let conflicting_block_number = reorg_block_hashes[0].block_number;
        tracing::warn!(
            ?reorg_block_hashes,
            conflicting_block_number,
            "Found reorged blocks. Rolling back to last good root before conflicting block."
        );

        // Find the last RootRecorded event strictly before the conflicting block.
        // Use log_index=0 so the query returns any root at block < conflicting_block_number.
        let rollback_target = tx
            .world_id_registry_events()
            .await?
            .get_root_recorded_before(WorldIdRegistryEventId {
                block_number: conflicting_block_number,
                log_index: 0,
            })
            .await?;

        let Some(target) = rollback_target else {
            return Err(BlockchainSyncCheckError::ShouldNotHappen(format!(
                "no RootRecorded event found before conflicting block {conflicting_block_number}"
            ))
            .into());
        };

        let mut rollback_executor = RollbackExecutor::new(&mut tx);
        rollback_executor
            .rollback_to_event((target.block_number, target.log_index))
            .await?;
    }

    tx.commit().await?;

    Ok(())
}

async fn check_latest_root(
    db: &DB,
    blockchain: &Blockchain,
    registry: &WorldIdRegistryInstance<DynProvider>,
    max_sync_backward_check_blocks: u64,
) -> IndexerResult<()> {
    let mut tx = db.transaction(IsolationLevel::Serializable).await?;

    let Some(latest_root_recorded_in_db) = tx
        .world_id_registry_events()
        .await?
        .get_latest_root_recorded()
        .await?
    else {
        return {
            tx.commit().await?;
            Ok(())
        };
    };

    if !is_valid_root_and_block_hash(blockchain, registry, &latest_root_recorded_in_db).await? {
        handle_reorg(
            &mut tx,
            blockchain,
            registry,
            &latest_root_recorded_in_db,
            max_sync_backward_check_blocks,
        )
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

async fn is_valid_root_and_block_hash(
    blockchain: &Blockchain,
    registry: &WorldIdRegistryInstance<DynProvider>,
    event: &BlockchainEvent<RootRecordedEvent>,
) -> Result<bool, BlockchainSyncCheckError> {
    let Some(block_on_chain) = blockchain.get_block_by_number(event.block_number).await? else {
        tracing::warn!(
            block_number = event.block_number,
            "Event considered invalid due to matching block with same number not found on chain.",
        );
        return Ok(false);
    };

    let block_hash_on_chain: U256 = block_on_chain.hash().into();
    if block_hash_on_chain != event.block_hash {
        tracing::warn!(
            block_number = event.block_number,
            ?block_hash_on_chain,
            block_hash_in_db = ?event.block_hash,
            "Event considered invalid due to block hash mismatch with chain.",
        );
        return Ok(false);
    }

    let root = event.details.root;

    if !registry.isValidRoot(root).call().await? {
        tracing::warn!(
            block_number = event.block_number,
            ?root,
            "Event considered invalid due to root not being valid on chain.",
        );
        return Ok(false);
    }

    Ok(true)
}

async fn handle_reorg(
    tx: &mut PostgresDBTransaction<'_>,
    blockchain: &Blockchain,
    registry: &WorldIdRegistryInstance<DynProvider>,
    latest_event: &BlockchainEvent<RootRecordedEvent>,
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

    if !is_valid_root_and_block_hash(blockchain, registry, &events[0]).await? {
        return Err(BlockchainSyncCheckError::NoValidRootAfterBackwardBlocks().into());
    }

    let mut p = 0; // last known valid index
    let mut q = events.len() - 1;
    // Binary search for the latest valid root
    while p < q {
        let mid = (p + q).div_ceil(2);

        if is_valid_root_and_block_hash(blockchain, registry, &events[mid]).await? {
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

    Ok(())
}
