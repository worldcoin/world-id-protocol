use alloy::primitives::U256;
use sqlx::{Postgres, Row, postgres::PgRow};
use tracing::instrument;

use crate::{db::DBResult, invalid_field};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncLogKind {
    LeafUpdate,
    RollbackLeaf,
    RootVerification,
}

impl SyncLogKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeafUpdate => "leaf_update",
            Self::RollbackLeaf => "rollback_leaf",
            Self::RootVerification => "root_verification",
        }
    }
}

impl TryFrom<&str> for SyncLogKind {
    type Error = crate::db::DBError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "leaf_update" => Ok(Self::LeafUpdate),
            "rollback_leaf" => Ok(Self::RollbackLeaf),
            "root_verification" => Ok(Self::RootVerification),
            _ => Err(invalid_field!("kind", "unknown sync_log kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncLogEntry {
    pub sync_id: u64,
    pub kind: SyncLogKind,
    pub leaf_index: Option<u64>,
    pub commitment: Option<U256>,
    pub expected_root: Option<U256>,
    pub next_leaf_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootVerification {
    pub sync_id: u64,
    pub expected_root: U256,
    pub next_leaf_index: u64,
}

pub struct SyncLog<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> SyncLog<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            _marker: std::marker::PhantomData,
        }
    }

    #[instrument(level = "info", skip(self, commitment))]
    pub async fn insert_leaf_update(self, leaf_index: u64, commitment: U256) -> DBResult<u64> {
        self.insert_leaf_row(SyncLogKind::LeafUpdate, leaf_index, Some(commitment))
            .await
    }

    #[instrument(level = "info", skip(self, commitment))]
    pub async fn insert_rollback_leaf(
        self,
        leaf_index: u64,
        commitment: Option<U256>,
    ) -> DBResult<u64> {
        self.insert_leaf_row(SyncLogKind::RollbackLeaf, leaf_index, commitment)
            .await
    }

    async fn insert_leaf_row(
        self,
        kind: SyncLogKind,
        leaf_index: u64,
        commitment: Option<U256>,
    ) -> DBResult<u64> {
        let row = sqlx::query(
            r#"
                INSERT INTO sync_log (
                    kind,
                    leaf_index,
                    commitment
                ) VALUES ($1, $2, $3)
                RETURNING sync_id
            "#,
        )
        .bind(kind.as_str())
        .bind(leaf_index as i64)
        .bind(commitment)
        .fetch_one(self.executor)
        .await?;

        Ok(row.get::<i64, _>("sync_id") as u64)
    }

    #[instrument(level = "info", skip(self, expected_root))]
    pub async fn insert_root_verification(
        self,
        expected_root: U256,
        next_leaf_index: u64,
    ) -> DBResult<u64> {
        let row = sqlx::query(
            r#"
                INSERT INTO sync_log (
                    kind,
                    expected_root,
                    next_leaf_index
                ) VALUES ($1, $2, $3)
                RETURNING sync_id
            "#,
        )
        .bind(SyncLogKind::RootVerification.as_str())
        .bind(expected_root)
        .bind(next_leaf_index as i64)
        .fetch_one(self.executor)
        .await?;

        Ok(row.get::<i64, _>("sync_id") as u64)
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_max_sync_id(self) -> DBResult<u64> {
        let row = sqlx::query("SELECT coalesce(max(sync_id), 0) AS max_sync_id FROM sync_log")
            .fetch_one(self.executor)
            .await?;

        Ok(row.get::<i64, _>("max_sync_id") as u64)
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_after(self, sync_id: u64, limit: u64) -> DBResult<Vec<SyncLogEntry>> {
        let rows = sqlx::query(
            r#"
                SELECT
                    sync_id,
                    kind,
                    leaf_index,
                    commitment,
                    expected_root,
                    next_leaf_index
                FROM sync_log
                WHERE sync_id > $1
                ORDER BY sync_id ASC
                LIMIT $2
            "#,
        )
        .bind(sync_id as i64)
        .bind(limit as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter().map(Self::map_entry).collect()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_root_verification_at(
        self,
        sync_id: u64,
    ) -> DBResult<Option<RootVerification>> {
        let result = sqlx::query(
            r#"
                SELECT
                    sync_id,
                    expected_root,
                    next_leaf_index
                FROM sync_log
                WHERE kind = 'root_verification'
                  AND sync_id <= $1
                ORDER BY sync_id DESC
                LIMIT 1
            "#,
        )
        .bind(sync_id as i64)
        .fetch_optional(self.executor)
        .await?;

        result
            .map(|row| Self::map_root_verification(&row))
            .transpose()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_leaf_values_at(
        self,
        sync_id: u64,
    ) -> DBResult<Vec<(u64, Option<U256>)>> {
        let rows = sqlx::query(
            r#"
                SELECT DISTINCT ON (leaf_index)
                    leaf_index,
                    commitment
                FROM sync_log
                WHERE leaf_index IS NOT NULL
                  AND sync_id <= $1
                  AND kind IN ('leaf_update', 'rollback_leaf')
                ORDER BY leaf_index ASC, sync_id DESC
            "#,
        )
        .bind(sync_id as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter()
            .map(|row| {
                Ok((
                    row.get::<i64, _>("leaf_index") as u64,
                    row.get::<Option<U256>, _>("commitment"),
                ))
            })
            .collect()
    }

    fn map_entry(row: &PgRow) -> DBResult<SyncLogEntry> {
        Ok(SyncLogEntry {
            sync_id: row.get::<i64, _>("sync_id") as u64,
            kind: SyncLogKind::try_from(row.get::<&str, _>("kind"))?,
            leaf_index: row.get::<Option<i64>, _>("leaf_index").map(|v| v as u64),
            commitment: row.get::<Option<U256>, _>("commitment"),
            expected_root: row.get::<Option<U256>, _>("expected_root"),
            next_leaf_index: row
                .get::<Option<i64>, _>("next_leaf_index")
                .map(|v| v as u64),
        })
    }

    fn map_root_verification(row: &PgRow) -> DBResult<RootVerification> {
        let expected_root = row.get::<Option<U256>, _>("expected_root").ok_or_else(|| {
            invalid_field!("expected_root", "root verification row is missing root")
        })?;
        let next_leaf_index = row
            .get::<Option<i64>, _>("next_leaf_index")
            .ok_or_else(|| {
                invalid_field!(
                    "next_leaf_index",
                    "root verification row is missing next leaf index"
                )
            })?;

        Ok(RootVerification {
            sync_id: row.get::<i64, _>("sync_id") as u64,
            expected_root,
            next_leaf_index: next_leaf_index as u64,
        })
    }
}
