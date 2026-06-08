use std::collections::HashMap;

use alloy::primitives::U256;
use futures_util::{Stream, StreamExt as _};
use sqlx::{Postgres, Row, postgres::PgRow};
use tracing::instrument;

use crate::{
    batch::{Batch, BatchHeader, BatchKind, BatchOrigin, LeafChange, Persisted},
    db::{DBResult, PostgresDBTransaction},
};

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

    #[instrument(level = "info", skip(self, header))]
    pub async fn insert_batch_header(self, header: &BatchHeader) -> DBResult<u64> {
        let origin = &header.origin;

        let row = sqlx::query(
            r#"
                INSERT INTO sync_batch (
                    kind,
                    expected_root,
                    next_leaf_index,
                    block_number,
                    log_index,
                    onchain_timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING batch_id
            "#,
        )
        .bind(header.kind.as_str())
        .bind(header.expected_root)
        .bind(header.next_leaf_index as i64)
        .bind(origin.block_number as i64)
        .bind(origin.log_index as i64)
        .bind(origin.onchain_timestamp as i64)
        .fetch_one(self.executor)
        .await?;

        Ok(row.get::<i64, _>("batch_id") as u64)
    }

    #[instrument(level = "info", skip(self, change))]
    pub async fn insert_leaf_change(self, batch_id: u64, change: &LeafChange) -> DBResult<()> {
        sqlx::query(
            r#"
                INSERT INTO sync_leaf_change (
                    batch_id,
                    leaf_index,
                    commitment
                ) VALUES ($1, $2, $3)
            "#,
        )
        .bind(batch_id as i64)
        .bind(change.leaf_index as i64)
        .bind(change.commitment)
        .execute(self.executor)
        .await?;

        Ok(())
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_max_batch_id(self) -> DBResult<u64> {
        let row = sqlx::query("SELECT coalesce(max(batch_id), 0) AS max_batch_id FROM sync_batch")
            .fetch_one(self.executor)
            .await?;

        Ok(row.get::<i64, _>("max_batch_id") as u64)
    }

    /// Returns batches with `batch_id > from_batch_id`, ordered by ascending
    /// batch id.
    ///
    /// `to_batch_id`, when set, caps the range to `batch_id <= to_batch_id`.
    /// `limit`, when set, caps the number of batches returned (the cap applies
    /// to batches, not to the JOIN-expanded leaf-change rows). Note: The same
    /// thing can not be achieved with `to_batch_id` since `batch_id` may have gaps.
    #[instrument(level = "info", skip(self))]
    pub async fn get_batches(
        self,
        from_batch_id: u64,
        to_batch_id: Option<u64>,
        limit: Option<u64>,
    ) -> DBResult<Vec<Persisted<Batch>>> {
        let rows = sqlx::query(
            r#"
                SELECT
                    b.batch_id,
                    b.kind,
                    b.expected_root,
                    b.next_leaf_index,
                    b.block_number,
                    b.log_index,
                    b.onchain_timestamp,
                    c.leaf_index,
                    c.commitment,
                    c.change_id
                FROM sync_batch b
                LEFT JOIN sync_leaf_change c ON c.batch_id = b.batch_id
                WHERE b.batch_id IN (
                    SELECT batch_id
                    FROM sync_batch
                    WHERE batch_id > $1
                      AND ($2::int8 IS NULL OR batch_id <= $2)
                    ORDER BY batch_id ASC
                    LIMIT $3
                )
                ORDER BY b.batch_id ASC, c.change_id ASC
            "#,
        )
        .bind(from_batch_id as i64)
        .bind(to_batch_id.map(|v| v as i64))
        .bind(limit.map(|v| v as i64))
        .fetch_all(self.executor)
        .await?;

        Self::group_batch_rows(rows)
    }

    /// Returns the exact batch row at `batch_id`, if present.
    #[instrument(level = "info", skip(self))]
    pub async fn get_batch_at(self, batch_id: u64) -> DBResult<Option<Persisted<BatchHeader>>> {
        let result = sqlx::query(
            r#"
                SELECT
                    batch_id,
                    kind,
                    expected_root,
                    next_leaf_index,
                    block_number,
                    log_index,
                    onchain_timestamp
                FROM sync_batch
                WHERE batch_id = $1
            "#,
        )
        .bind(batch_id as i64)
        .fetch_optional(self.executor)
        .await?;

        result
            .map(|row| Self::map_persisted_header(&row))
            .transpose()
    }

    /// Returns the latest batch at or before `batch_id`.
    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_batch_at(
        self,
        batch_id: u64,
    ) -> DBResult<Option<Persisted<BatchHeader>>> {
        let result = sqlx::query(
            r#"
                SELECT
                    batch_id,
                    kind,
                    expected_root,
                    next_leaf_index,
                    block_number,
                    log_index,
                    onchain_timestamp
                FROM sync_batch
                WHERE batch_id <= $1
                ORDER BY batch_id DESC
                LIMIT 1
            "#,
        )
        .bind(batch_id as i64)
        .fetch_optional(self.executor)
        .await?;

        result
            .map(|row| Self::map_persisted_header(&row))
            .transpose()
    }

    /// Latest batch_id whose checkpoint root equals `root`, if any.
    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_batch_id_by_root(self, root: U256) -> DBResult<Option<u64>> {
        let row = sqlx::query(
            "SELECT max(batch_id) AS batch_id FROM sync_batch WHERE expected_root = $1",
        )
        .bind(root)
        .fetch_one(self.executor)
        .await?;

        Ok(row.get::<Option<i64>, _>("batch_id").map(|v| v as u64))
    }

    /// Streams the latest known value for each leaf at or before `batch_id`.
    /// Note: Stream is necessary here because there is one leaf per world id account (millions of accounts) and we need a consistent view of the tree.
    #[instrument(level = "info", skip(self))]
    pub fn stream_latest_leaf_values_at(
        self,
        batch_id: u64,
    ) -> impl Stream<Item = DBResult<(u64, Option<U256>)>> + 'a {
        sqlx::query(
            r#"
                SELECT DISTINCT ON (c.leaf_index)
                    c.leaf_index,
                    c.commitment
                FROM sync_leaf_change c
                JOIN sync_batch b USING (batch_id)
                WHERE b.batch_id <= $1
                ORDER BY c.leaf_index ASC, b.batch_id DESC, c.change_id DESC
            "#,
        )
        .bind(batch_id as i64)
        .fetch(self.executor)
        .map(|row_result| {
            let row = row_result?;
            Ok((
                row.get::<i64, _>("leaf_index") as u64,
                row.get::<Option<U256>, _>("commitment"),
            ))
        })
    }

    // Conversion helper `sync_batch` rows to `Persisted<BatchHeader>`.
    fn map_persisted_header(row: &PgRow) -> DBResult<Persisted<BatchHeader>> {
        Ok(Persisted {
            batch_id: row.get::<i64, _>("batch_id") as u64,
            inner: BatchHeader {
                kind: BatchKind::try_from(row.get::<&str, _>("kind"))?,
                expected_root: row.get::<U256, _>("expected_root"),
                next_leaf_index: row.get::<i64, _>("next_leaf_index") as u64,
                origin: BatchOrigin {
                    block_number: row.get::<i64, _>("block_number") as u64,
                    log_index: row.get::<i64, _>("log_index") as u64,
                    onchain_timestamp: row.get::<i64, _>("onchain_timestamp") as u64,
                },
            },
        })
    }

    // Conversion helper for JOIN-expanded `sync_batch`/`sync_leaf_change` rows
    // into `Persisted<Batch>`, preserving the query's batch ordering.
    fn group_batch_rows(rows: Vec<PgRow>) -> DBResult<Vec<Persisted<Batch>>> {
        let mut batches_map: HashMap<u64, Persisted<Batch>> = HashMap::new();
        let mut order = Vec::new();

        for row in rows {
            let batch_id = row.get::<i64, _>("batch_id") as u64;
            if !batches_map.contains_key(&batch_id) {
                order.push(batch_id);
                batches_map.insert(
                    batch_id,
                    Persisted {
                        batch_id,
                        inner: Batch {
                            header: BatchHeader {
                                kind: BatchKind::try_from(row.get::<&str, _>("kind"))?,
                                expected_root: row.get::<U256, _>("expected_root"),
                                next_leaf_index: row.get::<i64, _>("next_leaf_index") as u64,
                                origin: BatchOrigin {
                                    block_number: row.get::<i64, _>("block_number") as u64,
                                    log_index: row.get::<i64, _>("log_index") as u64,
                                    onchain_timestamp: row.get::<i64, _>("onchain_timestamp")
                                        as u64,
                                },
                            },
                            changes: Vec::new(),
                        },
                    },
                );
            }

            if let Some(leaf_index) = row.get::<Option<i64>, _>("leaf_index") {
                batches_map
                    .get_mut(&batch_id)
                    .expect("batch inserted above")
                    .inner
                    .changes
                    .push(LeafChange {
                        leaf_index: leaf_index as u64,
                        commitment: row.get::<Option<U256>, _>("commitment"),
                    });
            }
        }

        Ok(order
            .into_iter()
            .map(|batch_id| {
                batches_map
                    .remove(&batch_id)
                    .expect("batch id present in order")
            })
            .collect())
    }
}

/// Persist a batch and its leaf changes within a transaction.
pub async fn insert_sync_log_batch(
    tx: &mut PostgresDBTransaction<'_>,
    batch: &Batch,
) -> DBResult<u64> {
    let batch_id = tx
        .sync_log()
        .await?
        .insert_batch_header(&batch.header)
        .await?;
    for change in &batch.changes {
        tx.sync_log()
            .await?
            .insert_leaf_change(batch_id, change)
            .await?;
    }
    Ok(batch_id)
}
