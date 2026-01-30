use core::fmt;

use alloy::primitives::U256;
use sqlx::{PgPool, Row, postgres::PgRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorldTreeRootId {
    pub block_number: u64,
    pub log_index: u64,
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
    type Error = anyhow::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "root_recorded" => Ok(WorldTreeRootEventType::RootRecorded),
            _ => Err(anyhow::anyhow!("Unknown event type: {}", value)),
        }
    }
}

pub struct WorldTreeRoots<'a> {
    pool: &'a PgPool,
    table_name: String,
}

impl<'a> WorldTreeRoots<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self {
            pool,
            table_name: "world_tree_roots".to_string(),
        }
    }

    pub async fn get_latest_id(&self) -> anyhow::Result<Option<WorldTreeRootId>> {
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

    pub async fn insert_event(
        &self,
        block_number: u64,
        log_index: u64,
        event_type: WorldTreeRootEventType,
        tx_hash: &U256,
        root: &U256,
        timestamp: &U256,
    ) -> anyhow::Result<()> {
        sqlx::query(&format!(
            r#"
                INSERT INTO {} (
                    block_number,
                    log_index,
                    event_type,
                    tx_hash,
                    root,
                    root_timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            self.table_name
        ))
        .bind(block_number as i64)
        .bind(log_index as i64)
        .bind(event_type.to_string())
        .bind(tx_hash)
        .bind(root)
        .bind(timestamp)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    fn map_row_to_event_id(&self, row: &PgRow) -> anyhow::Result<WorldTreeRootId> {
        Ok(WorldTreeRootId {
            block_number: row.get::<i64, _>("block_number") as u64,
            log_index: row.get::<i64, _>("log_index") as u64,
        })
    }

    pub fn map_row_to_world_tree_event(&self, row: &PgRow) -> anyhow::Result<WorldTreeRoot> {
        Ok(WorldTreeRoot {
            id: self.map_row_to_event_id(row)?,
            tx_hash: row.get::<U256, _>("tx_hash"),
            event_type: WorldTreeRootEventType::try_from(row.get::<&str, _>("event_type"))?,
            root: row.get::<U256, _>("root"),
            timestamp: row.get::<U256, _>("root_timestamp"),
        })
    }
}
