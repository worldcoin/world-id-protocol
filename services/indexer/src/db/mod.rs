use alloy::primitives::U256;
use futures_util::{Stream, StreamExt as _};
use sqlx::{
    Acquire, Executor, PgConnection, PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions,
};
use thiserror::Error;

mod accounts;
mod world_tree_events;
mod world_tree_roots;

pub use accounts::Accounts;
pub use world_tree_events::{WorldTreeEventId, WorldTreeEventType, WorldTreeEvents};
pub use world_tree_roots::{
    WorldTreeRoot, WorldTreeRootEventType, WorldTreeRootId, WorldTreeRoots,
};

pub type DBResult<T> = Result<T, DBError>;

#[derive(Debug, Error)]
pub enum DBError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("invalid event type: {0}")]
    InvalidEventType(String),
}

// Type alias for convenience (for potential future generics)
pub type DB = PostgresDB;

#[derive(Clone)]
pub struct PostgresDB {
    pool: PgPool,
}

impl PostgresDB {
    pub async fn new(db_url: &str, max_connections: Option<u32>) -> DBResult<Self> {
        tracing::info!("Connecting to DB...");
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.unwrap_or(10))
            .connect(db_url)
            .await?;
        tracing::info!("🟢 Connection to DB successful.");

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> DBResult<()> {
        // Run sqlx migrations from ./migrations
        tracing::info!("Running migrations...");
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        tracing::info!("🟢 Migrations synced successfully.");
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn transaction(
        &self,
        isolation_level: IsolationLevel,
    ) -> DBResult<PostgresDBTransaction<'_>> {
        PostgresDBTransaction::new(&self.pool, isolation_level).await
    }

    pub fn world_tree_events(&self) -> WorldTreeEvents<'_, &PgPool> {
        WorldTreeEvents::with_executor(&self.pool)
    }

    pub fn world_tree_roots(&self) -> WorldTreeRoots<'_, &PgPool> {
        WorldTreeRoots::with_executor(&self.pool)
    }

    pub fn accounts(&self) -> Accounts<'_, &PgPool> {
        Accounts::with_executor(&self.pool)
    }

    pub async fn ping(&self) -> DBResult<()> {
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }
}

/// Transaction isolation level
///
/// PG docs: https://www.postgresql.org/docs/current/transaction-iso.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

pub struct PostgresDBTransaction<'a> {
    tx: Transaction<'a, Postgres>,
}

impl<'a> PostgresDBTransaction<'a> {
    async fn new(pool: &PgPool, isolation_level: IsolationLevel) -> DBResult<Self> {
        let mut tx = pool.begin().await?;

        let conn = tx.acquire().await?;

        match isolation_level {
            IsolationLevel::ReadUncommitted => {
                sqlx::query("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
                    .execute(&mut *conn)
                    .await?;
            }
            IsolationLevel::ReadCommitted => {
                sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    .execute(&mut *conn)
                    .await?;
            }
            IsolationLevel::RepeatableRead => {
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                    .execute(&mut *conn)
                    .await?;
            }
            IsolationLevel::Serializable => {
                sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                    .execute(&mut *conn)
                    .await?;
            }
        }

        Ok(Self { tx })
    }

    /// Get a world_tree_events table accessor for executing a single query.
    /// Multiple calls to this or other table methods are allowed within the same transaction.
    pub async fn world_tree_events(&mut self) -> DBResult<WorldTreeEvents<'_, &mut PgConnection>> {
        let conn = self.tx.acquire().await?;
        Ok(WorldTreeEvents::with_executor(conn))
    }

    /// Get a world_tree_roots table accessor for executing a single query.
    pub async fn world_tree_roots(&mut self) -> DBResult<WorldTreeRoots<'_, &mut PgConnection>> {
        let conn = self.tx.acquire().await?;
        Ok(WorldTreeRoots::with_executor(conn))
    }

    /// Get an accounts table accessor for executing a single query.
    pub async fn accounts(&mut self) -> DBResult<Accounts<'_, &mut PgConnection>> {
        let conn = self.tx.acquire().await?;
        Ok(Accounts::with_executor(conn))
    }

    pub async fn commit(self) -> DBResult<()> {
        Ok(self.tx.commit().await?)
    }

    pub async fn rollback(self) -> DBResult<()> {
        Ok(self.tx.rollback().await?)
    }
}

// =============================================================================
// Tree-related DB queries (extracted from tree module)
// =============================================================================

pub fn stream_leaves<'a, E>(executor: E) -> impl Stream<Item = DBResult<(u64, U256)>> + 'a
where
    E: Executor<'a, Database = Postgres> + 'a,
{
    sqlx::query(
        "SELECT leaf_index, offchain_signer_commitment
         FROM accounts
         ORDER BY leaf_index ASC",
    )
    .fetch(executor)
    .map(|row_result| {
        let row = row_result?;
        let leaf_index = row.get::<U256, _>("leaf_index");
        let leaf_index = leaf_index.as_limbs()[0];
        let commitment = row.get::<U256, _>("offchain_signer_commitment");
        Ok((leaf_index, commitment))
    })
}
