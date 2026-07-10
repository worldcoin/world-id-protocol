use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use backon::{ConstantBuilder, Retryable as _};
use eyre::Context as _;
use itertools::Itertools;
use sqlx::PgPool;
use taceo_nodes_common::postgres::{CreateSchema, PostgresConfig};
use tracing::instrument;

use crate::{accountant_service::RpCount, api::BillableRpRequest};

type Result<T> = std::result::Result<T, PostgresDbError>;

/// Postgres-backed store implementing both [`SecretManager`] and [`ChainCursorStorage`] on a shared `PgPool`.
#[derive(Clone, Debug)]
pub struct PostgresDb {
    pool: PgPool,
    backoff_strategy: ConstantBuilder,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PostgresDbError {
    #[error("error in postgres DB: {0}")]
    DbError(#[from] sqlx::Error),
    #[error("internal error postgres DB: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl PostgresDb {
    /// Initializes a [`PostgresDb`] by building the connection pool, ensuring the configured schema exists, and running all pending migrations.
    ///
    /// # Errors
    /// Returns an error if creating the database pool fails, or if running the migrations fails.
    #[instrument(level = "info", skip_all)]
    pub async fn init(db_config: &PostgresConfig) -> eyre::Result<Self> {
        tracing::info!("init PgPool with schema: {}", db_config.schema);
        let pool = taceo_nodes_common::postgres::pg_pool_with_schema(db_config, CreateSchema::Yes)
            .await
            .context("while creating pool")?;
        // We create the pool eagerly, so running migrations here should not hit pool-acquire retries.
        tracing::trace!("potentially running migrations..");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("while running migrations")?;

        Ok(Self {
            pool,
            backoff_strategy: ConstantBuilder::new()
                .with_max_times(db_config.max_retries.get())
                .with_delay(db_config.retry_delay),
        })
    }

    pub(crate) async fn store_request_batch(
        &self,
        epochs: Vec<u32>,
        rp_requests: Vec<BillableRpRequest>,
    ) -> Result<()> {
        if epochs.len() != rp_requests.len() {
            return Err(eyre::eyre!("epochs and rp_requests must have the same length").into());
        }
        let rp_ids = rp_requests
            .iter()
            .map(|r| r.rp_id.into_inner() as i64)
            .collect_vec();
        let epochs = epochs.iter().map(|e| *e as i64).collect_vec();
        let nonces = rp_requests
            .iter()
            .map(|r| to_db_ark_serialize_uncompressed(&r.nonce))
            .collect_vec();
        let created_ats = rp_requests
            .iter()
            .map(|r| r.created_at as i64)
            .collect_vec();
        let expires_ats = rp_requests
            .iter()
            .map(|r| r.expires_at as i64)
            .collect_vec();
        let signatures = rp_requests
            .iter()
            .map(|r| r.signature.map(Vec::<u8>::from))
            .collect_vec();

        let batch_insert = || async {
            Ok(sqlx::query(
                "
                INSERT INTO rp_signatures
                    (rp_id, epoch, nonce, signed_created_at, signed_expires_at, signature)
                SELECT * FROM UNNEST(
                    $1::bigint[],
                    $2::bigint[],
                    $3::bytea[],
                    $4::bigint[],
                    $5::bigint[],
                    $6::bytea[]
                )
                ON CONFLICT (rp_id, nonce, epoch) DO NOTHING
            ",
            )
            .bind(&rp_ids)
            .bind(&epochs)
            .bind(&nonces)
            .bind(&created_ats)
            .bind(&expires_ats)
            .bind(&signatures)
            .execute(&self.pool)
            .await?
            .rows_affected())
        };

        let _rows_affected = self.with_retry("store-request-batch", batch_insert).await?;

        Ok(())
    }

    /// Returns the last epoch the accountant submitted votes for, if any.
    ///
    /// Starts at -1 if no epoch has been processed yet.
    pub(crate) async fn get_epoch_cursor(&self) -> Result<i64> {
        let query = || async {
            Ok(
                sqlx::query_scalar::<_, i64>("SELECT epoch FROM epoch_cursor WHERE id")
                    .fetch_one(&self.pool)
                    .await?,
            )
        };
        self.with_retry("get-epoch-cursor", query).await
    }

    /// Records `epoch` as the last epoch the accountant voted for.
    pub(crate) async fn set_epoch_cursor(&self, epoch: u32) -> Result<()> {
        let epoch = i64::from(epoch);
        let query = || async {
            Ok(sqlx::query(
                "
                INSERT INTO epoch_cursor (id, epoch) VALUES (TRUE, $1)
                ON CONFLICT (id) DO UPDATE SET epoch = EXCLUDED.epoch
            ",
            )
            .bind(epoch)
            .execute(&self.pool)
            .await?)
        };
        self.with_retry("set-epoch-cursor", query).await?;
        Ok(())
    }

    /// Returns the number of requests observed per RP for `epoch`, ascending by `rp_id` (as
    /// required by `submitBillingVotes`).
    pub(crate) async fn rp_counts_for_epoch(&self, epoch: u32) -> Result<Vec<RpCount>> {
        let epoch = i64::from(epoch);
        let query = || async {
            Ok(sqlx::query_as::<_, (i64, i64)>(
                "
                SELECT rp_id, COUNT(*) FROM rp_signatures
                WHERE epoch = $1
                GROUP BY rp_id
                ORDER BY rp_id
            ",
            )
            .bind(epoch)
            .fetch_all(&self.pool)
            .await?)
        };
        let rows = self.with_retry("rp-counts-for-epoch", query).await?;
        Ok(rows
            .into_iter()
            .map(|(rp_id, count)| RpCount {
                rpId: rp_id as u64,
                count: count as u64,
            })
            .collect())
    }

    async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        f.retry(self.backoff_strategy)
            .sleep(tokio::time::sleep)
            .when(is_retryable_error)
            .notify(|err, duration| {
                tracing::warn!(%err, "Retrying {op_name} in db after {duration:?}");
            })
            .await
    }
}

#[inline]
fn is_retryable_error(e: &PostgresDbError) -> bool {
    match e {
        PostgresDbError::DbError(err) => {
            match err {
                // structural / driver-level errors
                sqlx::Error::PoolTimedOut
                | sqlx::Error::Io(_)
                | sqlx::Error::Tls(_)
                | sqlx::Error::Protocol(_)
                | sqlx::Error::AnyDriverError(_)
                | sqlx::Error::WorkerCrashed
                | sqlx::Error::BeginFailed => true,

                // serialization_failure and deadlock detected for transactions
                sqlx::Error::Database(db_err) => {
                    matches!(db_err.code().as_deref(), Some("40001" | "40P01"))
                }

                _ => false,
            }
        }
        _ => false,
    }
}

#[inline]
pub(crate) fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

#[inline]
#[expect(dead_code, reason = "here for later use")]
pub(crate) fn from_db_ark_serialize_uncompressed<T: CanonicalDeserialize>(b: Vec<u8>) -> Result<T> {
    T::deserialize_uncompressed(b.as_slice()).map_err(|e| {
        PostgresDbError::from(eyre::eyre!("Cannot deserialize bytes: DB not sane: {e}"))
    })
}
