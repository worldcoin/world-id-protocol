use core::fmt;

use alloy::primitives::U256;
use sqlx::{Postgres, Row, postgres::PgRow};
use tracing::instrument;

use crate::db::{DbError, DbResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorldTreeEventId {
    pub block_number: u64,
    pub log_index: u64,
}

impl From<(u64, u64)> for WorldTreeEventId {
    fn from(value: (u64, u64)) -> Self {
        WorldTreeEventId {
            block_number: value.0,
            log_index: value.1,
        }
    }
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
    type Error = DbError;

    fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
        match value {
            "account_created" => Ok(WorldTreeEventType::AccountCreated),
            "account_updated" => Ok(WorldTreeEventType::AccountUpdated),
            "account_recovered" => Ok(WorldTreeEventType::AccountRecovered),
            "authentication_inserted" => Ok(WorldTreeEventType::AuthenticationInserted),
            "authentication_removed" => Ok(WorldTreeEventType::AuthenticationRemoved),
            _ => Err(DbError::InvalidEventType {
                value: value.to_string(),
            }),
        }
    }
}

pub struct WorldTreeEvents<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    table_name: String,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> WorldTreeEvents<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            table_name: "world_tree_events".to_string(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn get_latest_block(self) -> DbResult<Option<u64>> {
        let rec: Option<(Option<i64>,)> = sqlx::query_as(&format!(
            "SELECT MAX(block_number) FROM {}",
            self.table_name
        ))
        .fetch_optional(self.executor)
        .await?;
        Ok(rec.and_then(|t| t.0.map(|v| v as u64)))
    }

    pub async fn get_latest_id(self) -> DbResult<Option<WorldTreeEventId>> {
        let table_name = self.table_name;
        let result = sqlx::query(&format!(
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
            table_name
        ))
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_event_id(&row)).transpose()
    }

    pub async fn get_event<T: Into<WorldTreeEventId>>(
        self,
        event_id: T,
    ) -> DbResult<Option<WorldTreeEvent>> {
        let event_id = event_id.into();
        let table_name = self.table_name;
        let result = sqlx::query(&format!(
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
                        block_number = $1 AND log_index = $2
                "#,
            table_name
        ))
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_event(&row)).transpose()
    }

    pub async fn get_after(
        self,
        event_id: WorldTreeEventId,
        limit: u64,
    ) -> DbResult<Vec<WorldTreeEvent>> {
        let table_name = self.table_name;
        let rows = sqlx::query(&format!(
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
                    log_index ASC
                LIMIT $3
            "#,
            table_name
        ))
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .bind(limit as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter().map(Self::map_event).collect()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn insert_event(
        self,
        leaf_index: &U256,
        event_type: WorldTreeEventType,
        offchain_signer_commitment: &U256,
        block_number: u64,
        tx_hash: &U256,
        log_index: u64,
    ) -> DbResult<()> {
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
        .execute(self.executor)
        .await?;

        Ok(())
    }

    fn map_event_id(row: &PgRow) -> DbResult<WorldTreeEventId> {
        Ok(WorldTreeEventId {
            block_number: row.get::<i64, _>("block_number") as u64,
            log_index: row.get::<i64, _>("log_index") as u64,
        })
    }

    fn map_event(row: &PgRow) -> DbResult<WorldTreeEvent> {
        Ok(WorldTreeEvent {
            id: Self::map_event_id(row)?,
            tx_hash: row.get::<U256, _>("tx_hash"),
            event_type: WorldTreeEventType::try_from(row.get::<&str, _>("event_type"))?,
            leaf_index: row.get::<U256, _>("leaf_index"),
            offchain_signer_commitment: row.get::<U256, _>("offchain_signer_commitment"),
        })
    }
}
