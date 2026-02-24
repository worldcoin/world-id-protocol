use std::time::Duration;

use alloy::primitives::U256;

use thiserror::Error;
use tracing::instrument;

use crate::{
    blockchain::Blockchain,
    db::{DB, IsolationLevel, PostgresDBTransaction},
    error::IndexerResult,
    rollback_executor::RollbackExecutor,
};

#[derive(Debug, Error)]
pub enum ReorgHandleError {
    #[error("reorg beyond conifugred max reorg blocks detectd.")]
    ReorgBeyondMaxReorgBlocks(),
    #[error("this should never happen: '{0}'.")]
    ShouldNotHappen(String),
}

/// Periodically checks that the local in-memory Merkle root remains valid on-chain.
#[instrument(level = "info", skip_all, fields(interval_secs, max_reorg_blocks))]
pub async fn blockchain_reorg_check_loop(
    interval_secs: u64,
    db: &DB,
    blockchain: &Blockchain,
    max_reorg_blocks: u64,
) -> IndexerResult<()> {
    tracing::info!(
        interval_secs,
        max_reorg_blocks,
        "Starting periodic blockchain reorg detector"
    );

    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        let mut tx = db.transaction(IsolationLevel::Serializable).await?;

        let latest_block = tx
            .world_id_registry_events()
            .await?
            .get_latest_block()
            .await?;

        let latest_block = match latest_block {
            Some(latest_block) => latest_block,
            None => continue,
        };

        if !is_same_block(&mut tx, blockchain, latest_block).await? {
            handle_reorg(&mut tx, blockchain, latest_block, max_reorg_blocks).await?;
        }

        tx.commit().await?;
    }
}

async fn is_same_block(
    tx: &mut PostgresDBTransaction<'_>,
    blockchain: &Blockchain,
    block_number: u64,
) -> IndexerResult<bool> {
    let block_hashes = tx
        .world_id_registry_events()
        .await?
        .get_block_hashes(block_number)
        .await?;

    if block_hashes.len() != 1 {
        tracing::warn!(
            "Block number {} has {} different block hashes in database ({:?}).",
            block_number,
            block_hashes.len(),
            block_hashes
        );
        return Ok(false);
    }

    let db_block_hash = block_hashes[0];

    let res = blockchain.get_block_by_number(block_number).await?;

    let res = match res {
        Some(res) => res,
        None => {
            tracing::warn!("Block number {} not found on chain.", block_number);
            return Ok(false);
        }
    };

    let chain_block_hash: U256 = res.hash().into();

    if chain_block_hash != db_block_hash {
        tracing::warn!(
            "Block number {} has different hash in db ({}) from the one on chain ({}).",
            block_number,
            db_block_hash,
            chain_block_hash
        );
        return Ok(false);
    }

    return Ok(true);
}

async fn handle_reorg<'a>(
    tx: &'a mut PostgresDBTransaction<'_>,
    blockchain: &Blockchain,
    latest_block: u64,
    max_reorg_blocks: u64,
) -> IndexerResult<()> {
    let mut latest_valid_block = latest_block;
    let mut earliest_valid_block = latest_block - max_reorg_blocks;

    if !is_same_block(tx, blockchain, earliest_valid_block).await? {
        return Err(ReorgHandleError::ReorgBeyondMaxReorgBlocks().into());
    }

    // Binary search for the latest valid block
    while earliest_valid_block < latest_valid_block {
        let mid = earliest_valid_block + (latest_valid_block - earliest_valid_block) / 2;

        if is_same_block(tx, blockchain, mid).await? {
            earliest_valid_block = mid + 1;
        } else {
            latest_valid_block = mid;
        }
    }

    let latest_valid_event_id = tx
        .world_id_registry_events()
        .await?
        .get_latest_id_for_block_number(earliest_valid_block)
        .await?
        .ok_or_else(|| ReorgHandleError::ShouldNotHappen("db should return latest event id for given block number as block number was taken from db".to_string()))?;

    let mut rollback_executor = RollbackExecutor::new(tx);
    rollback_executor
        .rollback_to_event(latest_valid_event_id)
        .await?;

    return Ok(());
}
