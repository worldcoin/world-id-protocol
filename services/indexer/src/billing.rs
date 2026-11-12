//! Syncs a WIP-107 Billing Contract's `BilledRpUpdated` events, so `GET /billing/billed-rps` can
//! serve the billed RPs without a chain read per request.
//!
//! The sync runs on its own checkpoint, independent of the registry pipeline: billing events
//! carry no Merkle root, so they cannot wait for one. A reorganization is detected by re-reading
//! the checkpoint block's hash; on a mismatch the events of the last [`REORG_REWIND_BLOCKS`] are
//! deleted and synced again, from the start block if it is that recent. A checkpoint block the RPC
//! does not have is retried, not rewound: the node may lag, and a chain that really got shorter
//! shows a different hash once it grows past it. Logs are read only `confirmations` blocks below
//! the head, so a node behind the provider's fallback that lags a little still has them, and every
//! log's block hash is checked against the canonical one, since the provider's fallback may answer
//! the log and block calls from different nodes. A node on another fork that leaves a log out goes
//! unnoticed; `confirmations` keeps that unlikely.
//!
//! Freshness is the timestamp of the synced block, so a stuck RPC or chain makes the endpoint
//! report the set as stale rather than serve it as current.

use std::{
    hash::{BuildHasher as _, Hasher as _},
    time::Duration,
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::B256,
    providers::{DynProvider, Provider as _},
    rpc::types::{Filter, Log},
    sol_types::SolEvent as _,
};
use thiserror::Error;
use world_id_registries::world_id_billing::WorldIdBilling::BilledRpUpdated;

use crate::{
    config::BillingConfig,
    db::{BilledRpEvent, Billing, BillingCheckpoint, DB, DBError, SyncedBlock},
    metrics,
};

/// How far back a detected reorganization rewinds. World Chain reorganizations of unsafe blocks
/// are far shallower; a deeper one would go unnoticed.
pub const REORG_REWIND_BLOCKS: u64 = 256;

const MAX_ERROR_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
enum SyncError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("database error: {0}")]
    Db(#[from] DBError),
    #[error("invalid BilledRpUpdated log: {0}")]
    InvalidLog(String),
    #[error("block {0} changed while syncing it")]
    BlockChanged(u64),
    #[error("block {0} not found")]
    BlockMissing(u64),
}

impl SyncError {
    const fn stage(&self) -> &'static str {
        match self {
            Self::Rpc(_) => "rpc",
            Self::Db(_) => "db",
            Self::InvalidLog(_) => "decode",
            Self::BlockChanged(_) => "block_changed",
            Self::BlockMissing(_) => "block_missing",
        }
    }
}

/// What one sync step did.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Synced a range, or rewound after a reorganization; more may follow at once.
    Advanced,
    /// Nothing new up to the chain head.
    CaughtUp,
}

/// Syncs the Billing Contract forever. Errors are logged, counted and retried with exponential
/// backoff and jitter; the loop never exits.
pub async fn billing_sync_loop(
    provider: DynProvider,
    db: DB,
    config: BillingConfig,
    batch_size: u64,
) -> eyre::Result<()> {
    tracing::info!(
        billing_contract = %config.address,
        start_block = config.start_block,
        confirmations = config.confirmations,
        "syncing the Billing Contract"
    );
    let mut chain_id = None;
    let mut failures = 0u32;
    loop {
        match sync_step(&provider, &db, config, batch_size.max(1), &mut chain_id).await {
            Ok(Step::Advanced) => failures = 0,
            Ok(Step::CaughtUp) => {
                failures = 0;
                tokio::time::sleep(config.poll_interval).await;
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                metrics::increment_billing_sync_errors(error.stage());
                let backoff = backoff(failures);
                tracing::warn!(
                    billing_contract = %config.address,
                    %error,
                    failures,
                    backoff_ms = backoff.as_millis(),
                    "Billing Contract sync failed; retrying"
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

async fn sync_step(
    provider: &DynProvider,
    db: &DB,
    config: BillingConfig,
    batch_size: u64,
    chain_id: &mut Option<u64>,
) -> Result<Step, SyncError> {
    let billing = db.billing(config.address);
    let chain_id = match *chain_id {
        Some(id) => id,
        None => *chain_id.insert(
            provider
                .get_chain_id()
                .await
                .map_err(|e| SyncError::Rpc(e.to_string()))?,
        ),
    };

    let checkpoint = billing.checkpoint().await?;
    if let Some(checkpoint) = checkpoint
        && (checkpoint.start_block != config.start_block || checkpoint.chain_id != chain_id)
    {
        let deleted = billing.reset().await?;
        tracing::warn!(
            billing_contract = %config.address,
            synced_start_block = checkpoint.start_block,
            start_block = config.start_block,
            synced_chain_id = checkpoint.chain_id,
            chain_id,
            deleted,
            "the start block or chain changed; restarting the Billing Contract sync"
        );
        return Ok(Step::Advanced);
    }

    let head = provider
        .get_block_number()
        .await
        .map_err(|e| SyncError::Rpc(e.to_string()))?;

    if let Some(checkpoint) = checkpoint {
        let synced = checkpoint.synced;
        if block(provider, synced.block_number).await?.hash != synced.block_hash {
            return rewind(provider, &billing, config, synced.block_number, head).await;
        }
    }

    // Logs are read only this far below the head, so every node behind the fallback has them.
    let safe_head = head.saturating_sub(config.confirmations);
    let from = checkpoint.map_or(config.start_block, |c| c.synced.block_number + 1);
    if from > safe_head {
        return Ok(Step::CaughtUp);
    }
    let to = from.saturating_add(batch_size - 1).min(safe_head);

    let to_block = block(provider, to).await?;
    let filter = Filter::new()
        .address(config.address)
        .event_signature(BilledRpUpdated::SIGNATURE_HASH)
        .from_block(from)
        .to_block(to);
    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(|e| SyncError::Rpc(e.to_string()))?;
    let events = logs.iter().map(decode).collect::<Result<Vec<_>, _>>()?;
    check_canonical(provider, &events, to, to_block.hash).await?;

    let caught_up = to == safe_head;
    billing
        .commit(
            &events,
            BillingCheckpoint {
                chain_id,
                start_block: config.start_block,
                synced: SyncedBlock {
                    block_number: to,
                    block_hash: to_block.hash,
                },
                // Mid-backfill the set is no more current than before.
                synced_at: if caught_up {
                    Some(to_block.timestamp)
                } else {
                    checkpoint.and_then(|c| c.synced_at)
                },
            },
        )
        .await?;
    metrics::set_billing_synced_block(to);
    Ok(if caught_up {
        Step::CaughtUp
    } else {
        Step::Advanced
    })
}

/// Deletes the events from `REORG_REWIND_BLOCKS` below `synced_block` on, and resyncs them.
async fn rewind(
    provider: &DynProvider,
    billing: &Billing<'_>,
    config: BillingConfig,
    synced_block: u64,
    head: u64,
) -> Result<Step, SyncError> {
    // From the lower of the two: on a shorter chain the blocks above `head` do not exist.
    let resume_from = synced_block
        .min(head)
        .saturating_sub(REORG_REWIND_BLOCKS)
        .max(config.start_block);
    let deleted = if resume_from == config.start_block {
        billing.reset().await?
    } else {
        let kept_through = resume_from - 1;
        billing
            .rewind(SyncedBlock {
                block_number: kept_through,
                block_hash: block(provider, kept_through).await?.hash,
            })
            .await?
    };
    metrics::increment_billing_reorgs();
    tracing::warn!(
        billing_contract = %config.address,
        synced_block,
        head,
        resume_from,
        deleted,
        "reorganization detected; rewound the Billing Contract sync"
    );
    Ok(Step::Advanced)
}

/// Fails unless every event comes from the canonical block of its number. `to_hash` is the
/// canonical hash of block `to`, already read.
async fn check_canonical(
    provider: &DynProvider,
    events: &[BilledRpEvent],
    to: u64,
    to_hash: B256,
) -> Result<(), SyncError> {
    // Events are sorted by block, so each block is looked up once.
    let mut checked: Option<(u64, B256)> = None;
    for event in events {
        let canonical = match checked {
            Some((number, hash)) if number == event.block_number => hash,
            _ if event.block_number == to => to_hash,
            _ => block(provider, event.block_number).await?.hash,
        };
        if event.block_hash != canonical {
            return Err(SyncError::BlockChanged(event.block_number));
        }
        checked = Some((event.block_number, canonical));
    }
    Ok(())
}

struct BlockRef {
    hash: B256,
    timestamp: u64,
}

/// Block `number`'s hash and timestamp. A block the RPC does not have is an error to retry: the
/// node answering may lag behind the one that reported the head.
async fn block(provider: &DynProvider, number: u64) -> Result<BlockRef, SyncError> {
    provider
        .get_block_by_number(BlockNumberOrTag::Number(number))
        .await
        .map_err(|e| SyncError::Rpc(e.to_string()))?
        .map(|block| BlockRef {
            hash: block.header.hash,
            timestamp: block.header.timestamp,
        })
        .ok_or(SyncError::BlockMissing(number))
}

fn decode(log: &Log) -> Result<BilledRpEvent, SyncError> {
    let missing = |field: &str| SyncError::InvalidLog(format!("missing {field}"));
    let event = BilledRpUpdated::decode_log(&log.inner)
        .map_err(|e| SyncError::InvalidLog(e.to_string()))?;
    Ok(BilledRpEvent {
        block_number: log.block_number.ok_or_else(|| missing("block_number"))?,
        log_index: log.log_index.ok_or_else(|| missing("log_index"))?,
        block_hash: log.block_hash.ok_or_else(|| missing("block_hash"))?,
        tx_hash: log
            .transaction_hash
            .ok_or_else(|| missing("transaction_hash"))?,
        rp_id: event.rpId,
        billed: event.billed,
    })
}

/// `2^(failures - 1)` seconds up to [`MAX_ERROR_BACKOFF`], minus up to half of it as jitter.
fn backoff(failures: u32) -> Duration {
    let base =
        Duration::from_secs(1u64 << failures.saturating_sub(1).min(5)).min(MAX_ERROR_BACKOFF);
    let jitter = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
        % (base.as_millis() as u64 / 2 + 1);
    base - Duration::from_millis(jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_up_to_the_cap_with_jitter() {
        for failures in 1..20 {
            let backoff = backoff(failures);
            let base = Duration::from_secs(1u64 << (failures - 1).min(5)).min(MAX_ERROR_BACKOFF);
            assert!(backoff <= base, "{failures}: {backoff:?} > {base:?}");
            assert!(
                backoff >= base / 2,
                "{failures}: {backoff:?} < half of {base:?}"
            );
        }
        assert!(backoff(30) <= MAX_ERROR_BACKOFF);
    }
}
