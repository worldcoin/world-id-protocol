use core::fmt;

use alloy::primitives::U256;
use sqlx::{Postgres, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorldTreeRootId {
    pub block_number: u64,
    pub log_index: u64,
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

pub struct WorldTreeRoots<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    table_name: String,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> WorldTreeRoots<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            table_name: "world_tree_roots".to_string(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn get_latest_id(self) -> anyhow::Result<Option<WorldTreeRootId>> {
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

        result
            .map(|row| {
                Ok(WorldTreeRootId {
                    block_number: row.get::<i64, _>("block_number") as u64,
                    log_index: row.get::<i64, _>("log_index") as u64,
                })
            })
            .transpose()
    }

    pub async fn insert_event(
        self,
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
        .execute(self.executor)
        .await?;
        Ok(())
    }
}
