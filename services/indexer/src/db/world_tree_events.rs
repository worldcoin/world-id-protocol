use core::fmt;

use alloy::primitives::U256;
use sqlx::{PgPool, Row, postgres::PgRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorldTreeEventId {
    pub block_number: u64,
    pub log_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorldTreeEvent {
    pub id: WorldTreeEventId,
    pub tx_hash: U256,
    pub event_type: WorldTreeEventType,
    pub leaf_index: U256,
    pub offchain_signer_commitment: U256,
}

/// Type of commitment update event stored in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldTreeEventType {
    AccountCreated,
    AccountUpdated,
    AccountRecovered,
    AuthenticationInserted,
    AuthenticationRemoved,
}

impl fmt::Display for WorldTreeEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorldTreeEventType::AccountCreated => write!(f, "account_created"),
            WorldTreeEventType::AccountUpdated => write!(f, "account_updated"),
            WorldTreeEventType::AccountRecovered => write!(f, "account_recovered"),
            WorldTreeEventType::AuthenticationInserted => write!(f, "authentication_inserted"),
            WorldTreeEventType::AuthenticationRemoved => write!(f, "authentication_removed"),
        }
    }
}

impl<'a> TryFrom<&'a str> for WorldTreeEventType {
    type Error = anyhow::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "account_created" => Ok(WorldTreeEventType::AccountCreated),
            "account_updated" => Ok(WorldTreeEventType::AccountUpdated),
            "account_recovered" => Ok(WorldTreeEventType::AccountRecovered),
            "authentication_inserted" => Ok(WorldTreeEventType::AuthenticationInserted),
            "authentication_removed" => Ok(WorldTreeEventType::AuthenticationRemoved),
            _ => Err(anyhow::anyhow!("Unknown event type: {}", value)),
        }
    }
}

pub struct WorldTreeEvents<'a> {
    pool: &'a PgPool,
    table_name: String,
}

impl<'a> WorldTreeEvents<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self {
            pool,
            table_name: "world_tree_events".to_string(),
        }
    }

    pub async fn get_latest_block(&self) -> anyhow::Result<Option<u64>> {
        let rec: Option<(Option<i64>,)> = sqlx::query_as(&format!(
            "SELECT MAX(block_number) FROM {}",
            self.table_name
        ))
        .fetch_optional(self.pool)
        .await?;
        Ok(rec.and_then(|t| t.0.map(|v| v as u64)))
    }

    pub async fn get_latest_id(&self) -> anyhow::Result<Option<WorldTreeEventId>> {
        sqlx::query(&format!(
            r#"
                SELECT
                    block_number,
                    log_index
                FROM {}
                ORDER BY
                    block_number DESC,
                    log_index DESC
                LIMIT 1
            "#,
            self.table_name
        ))
        .fetch_optional(self.pool)
        .await?
        .map(|row| self.map_row_to_event_id(&row))
        .transpose()
    }

    pub async fn get_after(
        &self,
        event_id: WorldTreeEventId,
        limit: u64,
    ) -> anyhow::Result<Vec<WorldTreeEvent>> {
        sqlx::query(&format!(
            r#"
                SELECT
                    block_number,
                    log_index,
                    leaf_index,
                    event_type,
                    offchain_signer_commitment,
                    tx_hash
                FROM {}
                WHERE
                    (block_number = $1 AND log_index > $2)
                    OR block_number > $1
                ORDER BY
                    block_number ASC,
                    log_index ASC,
                LIMIT $3
            "#,
            self.table_name
        ))
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .bind(limit as i64)
        .fetch_all(self.pool)
        .await?
        .iter()
        .map(|row| self.map_row_to_world_tree_event(row))
        .collect()
    }

    pub async fn insert_event(
        &self,
        leaf_index: &U256,
        event_type: WorldTreeEventType,
        offchain_signer_commitment: &U256,
        block_number: u64,
        tx_hash: &U256,
        log_index: u64,
    ) -> anyhow::Result<()> {
        sqlx::query(&format!(
            r#"
                INSERT INTO {} (
                    block_number,
                    log_index,
                    leaf_index,
                    event_type,
                    offchain_signer_commitment,
                    tx_hash
                ) VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            self.table_name
        ))
        .bind(block_number as i64)
        .bind(log_index as i64)
        .bind(leaf_index)
        .bind(event_type.to_string())
        .bind(offchain_signer_commitment)
        .bind(tx_hash)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    fn map_row_to_event_id(&self, row: &PgRow) -> anyhow::Result<WorldTreeEventId> {
        Ok(WorldTreeEventId {
            block_number: row.get::<i64, _>("block_number") as u64,
            log_index: row.get::<i64, _>("log_index") as u64,
        })
    }

    fn map_row_to_world_tree_event(&self, row: &PgRow) -> anyhow::Result<WorldTreeEvent> {
        Ok(WorldTreeEvent {
            id: self.map_row_to_event_id(row)?,
            tx_hash: row.get::<U256, _>("tx_hash"),
            event_type: WorldTreeEventType::try_from(row.get::<&str, _>("event_type"))?,
            leaf_index: row.get::<U256, _>("leaf_index"),
            offchain_signer_commitment: row.get::<U256, _>("offchain_signer_commitment"),
        })
    }
}
