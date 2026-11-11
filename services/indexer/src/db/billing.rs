//! Storage of a WIP-107 Billing Contract's `BilledRpUpdated` events.

use alloy::primitives::{Address, B256};
use sqlx::{PgPool, Row as _};
use tracing::instrument;

use super::{DBError, DBResult};

/// One `BilledRpUpdated` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilledRpEvent {
    pub block_number: u64,
    pub log_index: u64,
    pub block_hash: B256,
    pub tx_hash: B256,
    pub rp_id: u64,
    pub billed: bool,
}

/// The last block synced for a Billing Contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingCheckpoint {
    pub block_number: u64,
    pub block_hash: B256,
}

/// The RPs a Billing Contract bills, as of `block_number`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BilledRps {
    pub block_number: u64,
    /// Ascending.
    pub rp_ids: Vec<u64>,
}

pub struct Billing<'a> {
    pool: &'a PgPool,
    contract: Address,
}

impl<'a> Billing<'a> {
    pub const fn new(pool: &'a PgPool, contract: Address) -> Self {
        Self { pool, contract }
    }

    /// The last block synced for this contract, if any.
    #[instrument(level = "debug", skip(self))]
    pub async fn checkpoint(&self) -> DBResult<Option<BillingCheckpoint>> {
        let row = sqlx::query(
            "SELECT block_number, block_hash FROM billing_sync_checkpoints
             WHERE billing_contract = $1",
        )
        .bind(self.contract.as_slice())
        .fetch_optional(self.pool)
        .await?;
        row.map(|row| {
            Ok(BillingCheckpoint {
                block_number: block_number(&row, "block_number")?,
                block_hash: b256(&row, "block_hash")?,
            })
        })
        .transpose()
    }

    /// Stores `events`, all at or before `checkpoint`, and advances the checkpoint, atomically.
    /// An event already stored is kept as is, so a range can be synced again after a restart.
    #[instrument(level = "debug", skip(self, events), fields(events = events.len()))]
    pub async fn commit(
        &self,
        events: &[BilledRpEvent],
        checkpoint: BillingCheckpoint,
    ) -> DBResult<()> {
        let mut tx = self.pool.begin().await?;
        for event in events {
            sqlx::query(
                "INSERT INTO billed_rp_events
                     (billing_contract, block_number, log_index, block_hash, tx_hash, rp_id, billed)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (billing_contract, block_number, log_index) DO NOTHING",
            )
            .bind(self.contract.as_slice())
            .bind(to_i64(event.block_number, "block_number")?)
            .bind(to_i64(event.log_index, "log_index")?)
            .bind(event.block_hash.as_slice())
            .bind(event.tx_hash.as_slice())
            .bind(event.rp_id.to_be_bytes().as_slice())
            .bind(event.billed)
            .execute(&mut *tx)
            .await?;
        }
        upsert_checkpoint(&mut tx, self.contract, checkpoint).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the events after `checkpoint.block_number` and moves the checkpoint back to it,
    /// atomically.
    #[instrument(level = "info", skip(self))]
    pub async fn rewind(&self, checkpoint: BillingCheckpoint) -> DBResult<u64> {
        let mut tx = self.pool.begin().await?;
        let deleted = sqlx::query(
            "DELETE FROM billed_rp_events WHERE billing_contract = $1 AND block_number > $2",
        )
        .bind(self.contract.as_slice())
        .bind(to_i64(checkpoint.block_number, "block_number")?)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        upsert_checkpoint(&mut tx, self.contract, checkpoint).await?;
        tx.commit().await?;
        Ok(deleted)
    }

    /// Deletes all events and the checkpoint, atomically, so the next sync starts over from the
    /// start block.
    #[instrument(level = "info", skip(self))]
    pub async fn reset(&self) -> DBResult<u64> {
        let mut tx = self.pool.begin().await?;
        let deleted = sqlx::query("DELETE FROM billed_rp_events WHERE billing_contract = $1")
            .bind(self.contract.as_slice())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        sqlx::query("DELETE FROM billing_sync_checkpoints WHERE billing_contract = $1")
            .bind(self.contract.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(deleted)
    }

    /// The billed RPs as of the checkpoint, or `None` before the first sync.
    ///
    /// Reads the checkpoint and the events in one snapshot, so the set matches `block_number`.
    #[instrument(level = "debug", skip(self))]
    pub async fn billed_rps(&self) -> DBResult<Option<BilledRps>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let Some(checkpoint) = sqlx::query(
            "SELECT block_number FROM billing_sync_checkpoints WHERE billing_contract = $1",
        )
        .bind(self.contract.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        let rows = sqlx::query(
            "SELECT rp_id FROM (
                 SELECT DISTINCT ON (rp_id) rp_id, billed FROM billed_rp_events
                 WHERE billing_contract = $1
                 ORDER BY rp_id, block_number DESC, log_index DESC
             ) latest
             WHERE billed
             ORDER BY rp_id",
        )
        .bind(self.contract.as_slice())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let rp_ids = rows
            .iter()
            .map(|row| {
                let bytes: Vec<u8> = row.try_get("rp_id")?;
                let bytes: [u8; 8] = bytes.try_into().map_err(|_| DBError::InvalidEventField {
                    field: "rp_id".to_string(),
                    reason: "expected 8 bytes".to_string(),
                })?;
                Ok(u64::from_be_bytes(bytes))
            })
            .collect::<DBResult<_>>()?;
        Ok(Some(BilledRps {
            block_number: block_number(&checkpoint, "block_number")?,
            rp_ids,
        }))
    }
}

async fn upsert_checkpoint(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    contract: Address,
    checkpoint: BillingCheckpoint,
) -> DBResult<()> {
    sqlx::query(
        "INSERT INTO billing_sync_checkpoints (billing_contract, block_number, block_hash)
         VALUES ($1, $2, $3)
         ON CONFLICT (billing_contract)
         DO UPDATE SET block_number = EXCLUDED.block_number, block_hash = EXCLUDED.block_hash",
    )
    .bind(contract.as_slice())
    .bind(to_i64(checkpoint.block_number, "block_number")?)
    .bind(checkpoint.block_hash.as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn to_i64(value: u64, field: &str) -> DBResult<i64> {
    i64::try_from(value).map_err(|_| DBError::InvalidEventField {
        field: field.to_string(),
        reason: format!("{value} does not fit in bigint"),
    })
}

fn block_number(row: &sqlx::postgres::PgRow, column: &str) -> DBResult<u64> {
    let value: i64 = row.try_get(column)?;
    u64::try_from(value).map_err(|_| DBError::InvalidEventField {
        field: column.to_string(),
        reason: format!("{value} is negative"),
    })
}

fn b256(row: &sqlx::postgres::PgRow, column: &str) -> DBResult<B256> {
    let bytes: Vec<u8> = row.try_get(column)?;
    B256::try_from(bytes.as_slice()).map_err(|_| DBError::InvalidEventField {
        field: column.to_string(),
        reason: "expected 32 bytes".to_string(),
    })
}
