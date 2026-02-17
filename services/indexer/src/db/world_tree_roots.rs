use core::fmt;

use alloy::primitives::U256;
use sqlx::{Postgres, Row, postgres::PgRow};
use tracing::instrument;

use crate::db::{DBError, DBResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorldTreeRootId {
    pub block_number: u64,
    pub log_index: u64,
}

impl From<(u64, u64)> for WorldTreeRootId {
    fn from(value: (u64, u64)) -> Self {
        WorldTreeRootId {
            block_number: value.0,
            log_index: value.1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorldTreeRoot {
    pub id: WorldTreeRootId,
    pub tx_hash: U256,
    pub event_type: WorldTreeRootEventType,
    pub root: U256,
    pub timestamp: U256,
}

/// Type of commitment update event stored in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldTreeRootEventType {
    RootRecorded,
}

impl fmt::Display for WorldTreeRootEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorldTreeRootEventType::RootRecorded => write!(f, "root_recorded"),
        }
    }
}

impl<'a> TryFrom<&'a str> for WorldTreeRootEventType {
    type Error = DBError;

    fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
        match value {
            "root_recorded" => Ok(WorldTreeRootEventType::RootRecorded),
            _ => Err(DBError::InvalidEventType(value.to_string())),
        }
    }
}

pub struct WorldTreeRoots<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> WorldTreeRoots<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            _marker: std::marker::PhantomData,
        }
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_root<T: Into<WorldTreeRootId> + fmt::Debug>(
        self,
        root_id: T,
    ) -> DBResult<Option<WorldTreeRoot>> {
        let root_id = root_id.into();
        let result = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    event_type,
                    tx_hash,
                    root,
                    root_timestamp
                FROM world_tree_roots
                WHERE
                    block_number = $1 AND log_index = $2
            "#,
        )
        .bind(root_id.block_number as i64)
        .bind(root_id.log_index as i64)
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_root(&row)).transpose()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_id(self) -> DBResult<Option<WorldTreeRootId>> {
        let result = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index
                FROM world_tree_roots
                ORDER BY
                    block_number DESC,
                    log_index DESC
                LIMIT 1
            "#,
        )
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_root_id(&row)).transpose()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_block(self) -> DBResult<Option<u64>> {
        let rec: Option<(Option<i64>,)> =
            sqlx::query_as("SELECT MAX(block_number) FROM world_tree_roots")
                .fetch_optional(self.executor)
                .await?;
        Ok(rec.and_then(|t| t.0.map(|v| v as u64)))
    }

    /// Look up a root by its value (for restore validation).
    #[instrument(level = "info", skip(self))]
    pub async fn get_root_by_value(self, root: &U256) -> DBResult<Option<WorldTreeRoot>> {
        let result = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    event_type,
                    tx_hash,
                    root,
                    root_timestamp
                FROM world_tree_roots
                WHERE root = $1
            "#,
        )
        .bind(root)
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_root(&row)).transpose()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn insert_event(
        self,
        block_number: u64,
        log_index: u64,
        event_type: WorldTreeRootEventType,
        tx_hash: &U256,
        root: &U256,
        timestamp: &U256,
    ) -> DBResult<()> {
        sqlx::query(
            r#"
                INSERT INTO world_tree_roots (
                    block_number,
                    log_index,
                    event_type,
                    tx_hash,
                    root,
                    root_timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(block_number as i64)
        .bind(log_index as i64)
        .bind(event_type.to_string())
        .bind(tx_hash)
        .bind(root)
        .bind(timestamp)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    /// Delete roots after the given event_id
    #[instrument(level = "info", skip(self))]
    pub async fn delete_after_event(self, event_id: &crate::db::WorldTreeEventId) -> DBResult<u64> {
        let result = sqlx::query(
            r#"
                DELETE FROM world_tree_roots
                WHERE (block_number > $1)
                   OR (block_number = $1 AND log_index > $2)
            "#,
        )
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .execute(self.executor)
        .await?;

        Ok(result.rows_affected())
    }

    fn map_root_id(row: &PgRow) -> DBResult<WorldTreeRootId> {
        Ok(WorldTreeRootId {
            block_number: row.get::<i64, _>("block_number") as u64,
            log_index: row.get::<i64, _>("log_index") as u64,
        })
    }

    fn map_root(row: &PgRow) -> DBResult<WorldTreeRoot> {
        Ok(WorldTreeRoot {
            id: Self::map_root_id(row)?,
            tx_hash: row.get::<U256, _>("tx_hash"),
            event_type: WorldTreeRootEventType::try_from(row.get::<&str, _>("event_type"))?,
            root: row.get::<U256, _>("root"),
            timestamp: row.get::<U256, _>("root_timestamp"),
        })
    }
}
