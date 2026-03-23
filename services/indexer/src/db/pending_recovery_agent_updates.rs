use alloy::primitives::{Address, U160};
use sqlx::{Postgres, Row, postgres::PgRow};
use tracing::instrument;

use crate::db::DBResult;

/// Base delay in seconds for per-update retry backoff.
const RETRY_BACKOFF_BASE_SECONDS: f64 = 5.0;
/// Cap retry exponent to avoid unbounded delay growth.
const RETRY_BACKOFF_MAX_EXPONENT: i32 = 16;

/// A pending recovery agent update ready for execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRecoveryAgentUpdate {
    pub leaf_index: u64,
    pub new_recovery_agent: Address,
    pub attempts: i32,
}

pub struct PendingRecoveryAgentUpdates<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> PendingRecoveryAgentUpdates<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            _marker: std::marker::PhantomData,
        }
    }

    /// Upsert a pending recovery agent update from a `RecoveryAgentUpdateInitiated` event.
    #[instrument(level = "info", skip(self))]
    pub async fn upsert_pending(
        self,
        leaf_index: u64,
        new_recovery_agent: &Address,
        execute_after_unix: u64,
    ) -> DBResult<()> {
        sqlx::query(
            r#"
                INSERT INTO pending_recovery_agent_updates (
                    leaf_index,
                    new_recovery_agent,
                    execute_after,
                    status,
                    attempts,
                    last_attempt_at,
                    updated_at
                ) VALUES ($1, $2, to_timestamp($3::double precision), 'pending', 0, NULL, now())
                ON CONFLICT (leaf_index) DO UPDATE SET
                    new_recovery_agent = EXCLUDED.new_recovery_agent,
                    execute_after = EXCLUDED.execute_after,
                    status = 'pending',
                    attempts = 0,
                    last_attempt_at = NULL,
                    updated_at = now()
            "#,
        )
        .bind(leaf_index as i64)
        .bind(Self::address_to_u160(new_recovery_agent))
        .bind(execute_after_unix as f64)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    /// Mark a pending update as executed.
    #[instrument(level = "info", skip(self))]
    pub async fn mark_executed(self, leaf_index: u64) -> DBResult<()> {
        sqlx::query(
            r#"
                UPDATE pending_recovery_agent_updates
                SET status = 'executed', updated_at = now()
                WHERE leaf_index = $1
            "#,
        )
        .bind(leaf_index as i64)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    /// Mark a pending update as cancelled.
    #[instrument(level = "info", skip(self))]
    pub async fn mark_cancelled(self, leaf_index: u64) -> DBResult<()> {
        sqlx::query(
            r#"
                UPDATE pending_recovery_agent_updates
                SET status = 'cancelled', updated_at = now()
                WHERE leaf_index = $1
            "#,
        )
        .bind(leaf_index as i64)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    /// Fetch pending updates that are ready for execution (cooldown has elapsed).
    #[instrument(level = "info", skip(self))]
    pub async fn get_ready_for_execution(
        self,
        limit: i64,
    ) -> DBResult<Vec<PendingRecoveryAgentUpdate>> {
        let rows = sqlx::query(
            r#"
                SELECT leaf_index, new_recovery_agent, attempts
                FROM pending_recovery_agent_updates
                WHERE status = 'pending'
                  AND execute_after <= now()
                  AND (
                      last_attempt_at IS NULL
                      OR last_attempt_at + (($2::double precision * power(2::double precision, LEAST(attempts, $3))) * interval '1 second') <= now()
                  )
                ORDER BY execute_after ASC
                LIMIT $1
            "#,
        )
        .bind(limit)
        .bind(RETRY_BACKOFF_BASE_SECONDS)
        .bind(RETRY_BACKOFF_MAX_EXPONENT)
        .fetch_all(self.executor)
        .await?;

        rows.iter().map(Self::map_pending_update).collect()
    }

    /// Record an execution attempt (increment attempts and set last_attempt_at).
    #[instrument(level = "info", skip(self))]
    pub async fn record_attempt(self, leaf_index: u64) -> DBResult<()> {
        sqlx::query(
            r#"
                UPDATE pending_recovery_agent_updates
                SET attempts = attempts + 1,
                    last_attempt_at = now(),
                    updated_at = now()
                WHERE leaf_index = $1
            "#,
        )
        .bind(leaf_index as i64)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    fn map_pending_update(row: &PgRow) -> DBResult<PendingRecoveryAgentUpdate> {
        Ok(PendingRecoveryAgentUpdate {
            leaf_index: row.get::<i64, _>("leaf_index") as u64,
            new_recovery_agent: Address::from(row.get::<U160, _>("new_recovery_agent")),
            attempts: row.get::<i32, _>("attempts"),
        })
    }

    fn address_to_u160(address: &Address) -> U160 {
        (*address).into()
    }
}
