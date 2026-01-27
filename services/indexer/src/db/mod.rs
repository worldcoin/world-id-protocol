use alloy::primitives::U256;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

use crate::db::{accounts::Accounts, world_id_events::WorldIdEvents};

mod accounts;
mod world_id_events;

pub use world_id_events::{EventId, EventType};

#[derive(Clone)]
pub struct DB {
    pool: PgPool,
}

impl DB {
    pub async fn new(db_url: &str, max_connections: Option<u32>) -> anyhow::Result<DB> {
        tracing::info!("Connecting to DB...");
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.unwrap_or(10))
            .connect(db_url)
            .await?;
        tracing::info!("🟢 Connection to DB successful.");

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        // Run sqlx migrations from ./migrations
        tracing::info!("Running migrations...");
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        tracing::info!("🟢 Migrations synced successfully.");
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn world_id_events(&self) -> WorldIdEvents<'_> {
        WorldIdEvents::new(&self.pool)
    }

    pub fn accounts(&self) -> Accounts<'_> {
        Accounts::new(&self.pool)
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }
}

pub async fn fetch_recent_account_updates(
    pool: &PgPool,
    since: std::time::SystemTime,
) -> anyhow::Result<Vec<(U256, U256)>> {
    // Convert SystemTime to timestamp
    let since_duration = since
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let since_timestamp = since_duration.as_secs() as i64;

    // Query world_id_events for recent changes
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (leaf_index)
            leaf_index,
            new_commitment
        FROM world_id_events
        WHERE created_at > to_timestamp($1)
        ORDER BY leaf_index, created_at DESC
        "#,
    )
    .bind(since_timestamp)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(|row| {
            let leaf_index = row.get::<U256, _>("leaf_index");
            let commitment = row.get::<U256, _>("new_commitment");
            Ok((leaf_index, commitment))
        })
        .collect()
}

// =============================================================================
// Tree-related DB queries (extracted from tree module)
// =============================================================================

/// Count active (non-zero) leaves in the accounts table.
pub async fn get_active_leaf_count(pool: &PgPool) -> anyhow::Result<u64> {
    let result =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts WHERE leaf_index != $1")
            .bind(U256::ZERO)
            .fetch_one(pool)
            .await?;

    Ok(result as u64)
}

/// Count total events in world_id_events.
pub async fn get_total_event_count(pool: &PgPool) -> anyhow::Result<u64> {
    let result = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM world_id_events")
        .fetch_one(pool)
        .await?;

    Ok(result as u64)
}

pub async fn fetch_leaves_batch(
    pool: &PgPool,
    last_cursor: &U256,
    batch_size: i64,
) -> anyhow::Result<Vec<(U256, U256)>> {
    let rows = sqlx::query(
        "SELECT leaf_index, offchain_signer_commitment
         FROM accounts
         WHERE leaf_index > $1
         ORDER BY leaf_index ASC
         LIMIT $2",
    )
    .bind(last_cursor)
    .bind(batch_size)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(|row| {
            let leaf_index = row.get::<U256, _>("leaf_index");
            let commitment = row.get::<U256, _>("offchain_signer_commitment");
            Ok((leaf_index, commitment))
        })
        .collect()
}
