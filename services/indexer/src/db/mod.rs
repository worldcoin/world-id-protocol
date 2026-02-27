use sqlx::{Acquire, PgConnection, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use thiserror::Error;

mod accounts;
mod world_id_registry_events;

pub use accounts::Accounts;
pub use world_id_registry_events::{
    WorldIdRegistryEvent, WorldIdRegistryEventId, WorldIdRegistryEventType, WorldIdRegistryEvents,
};

pub type DBResult<T> = Result<T, DBError>;

#[derive(Debug, Error)]
pub enum DBError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("unknown event type: {0}")]
    UnknownEventType(String),
    #[error("missing required field '{field}' in event data")]
    MissingEventField { field: String },
    #[error("invalid value for field '{field}' in event data: {reason}")]
    InvalidEventField { field: String, reason: String },
    #[error("blockchain reorg detected: {0}")]
    ReorgDetected(String),
    #[error("contract call failed: {0}")]
    ContractCall(String),
}

// Helper macros for cleaner error construction
#[macro_export]
macro_rules! missing_field {
    ($field:expr) => {
        $crate::db::DBError::MissingEventField {
            field: $field.to_string(),
        }
    };
}

#[macro_export]
macro_rules! invalid_field {
    ($field:expr, $reason:expr) => {
        $crate::db::DBError::InvalidEventField {
            field: $field.to_string(),
            reason: $reason.to_string(),
        }
    };
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

    pub fn accounts(&self) -> Accounts<'_, &PgPool> {
        Accounts::with_executor(&self.pool)
    }

    pub fn world_id_registry_events(&self) -> WorldIdRegistryEvents<'_, &PgPool> {
        WorldIdRegistryEvents::with_executor(&self.pool)
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

    /// Get an accounts table accessor for executing a single query.
    pub async fn accounts(&mut self) -> DBResult<Accounts<'_, &mut PgConnection>> {
        let conn = self.tx.acquire().await?;
        Ok(Accounts::with_executor(conn))
    }

    /// Get a world_id_registry_events table accessor for executing a single query.
    pub async fn world_id_registry_events(
        &mut self,
    ) -> DBResult<WorldIdRegistryEvents<'_, &mut PgConnection>> {
        let conn = self.tx.acquire().await?;
        Ok(WorldIdRegistryEvents::with_executor(conn))
    }

    pub async fn commit(self) -> DBResult<()> {
        Ok(self.tx.commit().await?)
    }

    pub async fn rollback(self) -> DBResult<()> {
        Ok(self.tx.rollback().await?)
    }
}
