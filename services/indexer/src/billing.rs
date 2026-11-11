//! Syncs a WIP-107 Billing Contract's `BilledRpUpdated` events, so `GET /billing/billed-rps` can
//! serve the billed RPs without a chain read per request.
//!
//! The sync runs on its own checkpoint, independent of the registry pipeline: billing events
//! carry no Merkle root, so they cannot wait for one. A reorganization is detected by re-reading
//! the checkpoint block's hash; on a mismatch the events of the last [`REORG_REWIND_BLOCKS`] are
//! deleted and synced again.

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
    db::{BilledRpEvent, BillingCheckpoint, DB, DBError},
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
}

impl SyncError {
    const fn stage(&self) -> &'static str {
        match self {
            Self::Rpc(_) => "rpc",
            Self::Db(_) => "db",
            Self::InvalidLog(_) => "decode",
            Self::BlockChanged(_) => "block_changed",
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
    poll_interval: Duration,
) -> eyre::Result<()> {
    tracing::info!(billing_contract = %config.address, start_block = config.start_block, "syncing the Billing Contract");
    let mut failures = 0u32;
    loop {
        match sync_step(&provider, &db, config, batch_size.max(1)).await {
            Ok(Step::Advanced) => failures = 0,
            Ok(Step::CaughtUp) => {
                failures = 0;
                tokio::time::sleep(poll_interval).await;
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
) -> Result<Step, SyncError> {
    let billing = db.billing(config.address);
    let checkpoint = billing.checkpoint().await?;

    if let Some(checkpoint) = checkpoint {
        let current = block_hash(provider, checkpoint.block_number).await?;
        if current != checkpoint.block_hash {
            let target = checkpoint
                .block_number
                .saturating_sub(REORG_REWIND_BLOCKS)
                .max(config.start_block);
            let target = BillingCheckpoint {
                block_number: target,
                block_hash: block_hash(provider, target).await?,
            };
            let deleted = billing.rewind(target).await?;
            metrics::increment_billing_reorgs();
            metrics::set_billing_synced_block(target.block_number);
            tracing::warn!(
                billing_contract = %config.address,
                from_block = checkpoint.block_number,
                to_block = target.block_number,
                deleted,
                "reorganization detected; rewound the Billing Contract sync"
            );
            return Ok(Step::Advanced);
        }
    }

    let from = checkpoint.map_or(config.start_block, |c| c.block_number + 1);
    let head = provider
        .get_block_number()
        .await
        .map_err(|e| SyncError::Rpc(e.to_string()))?;
    if from > head {
        return Ok(Step::CaughtUp);
    }
    let to = from.saturating_add(batch_size - 1).min(head);

    let to_hash = block_hash(provider, to).await?;
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
    // Logs of the checkpoint block must come from the block whose hash is stored with it.
    if events
        .iter()
        .any(|event| event.block_number == to && event.block_hash != to_hash)
    {
        return Err(SyncError::BlockChanged(to));
    }

    billing
        .commit(
            &events,
            BillingCheckpoint {
                block_number: to,
                block_hash: to_hash,
            },
        )
        .await?;
    metrics::set_billing_synced_block(to);
    Ok(if to == head {
        Step::CaughtUp
    } else {
        Step::Advanced
    })
}

async fn block_hash(provider: &DynProvider, number: u64) -> Result<B256, SyncError> {
    provider
        .get_block_by_number(BlockNumberOrTag::Number(number))
        .await
        .map_err(|e| SyncError::Rpc(e.to_string()))?
        .map(|block| block.header.hash)
        .ok_or_else(|| SyncError::Rpc(format!("block {number} not found")))
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
