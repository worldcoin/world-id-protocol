use std::ops::Range;

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
        rp_requests: Vec<BillableRpRequest>,
    ) -> Result<()> {
        let rp_ids = rp_requests
            .iter()
            .map(|r| r.rp_id.into_inner() as i64)
            .collect_vec();
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
        let actions = rp_requests
            .iter()
            .map(|r| to_db_ark_serialize_uncompressed(&r.action))
            .collect_vec();
        let signatures = rp_requests
            .iter()
            .map(|r| r.signature.map(Vec::<u8>::from))
            .collect_vec();
        let wip101_datas = rp_requests
            .iter()
            .map(|r| r.wip101_data.clone())
            .collect_vec();

        let batch_insert = || async {
            Ok(sqlx::query(
                "
                INSERT INTO rp_signatures
                    (rp_id, nonce, created_at, expires_at, action, signature, wip101_data)
                SELECT * FROM UNNEST(
                    $1::bigint[],
                    $2::bytea[],
                    $3::bigint[],
                    $4::bigint[],
                    $5::bytea[],
                    $6::bytea[],
                    $7::bytea[]
                )
            ",
            )
            .bind(&rp_ids)
            .bind(&nonces)
            .bind(&created_ats)
            .bind(&expires_ats)
            .bind(&actions)
            .bind(&signatures)
            .bind(&wip101_datas)
            .execute(&self.pool)
            .await?
            .rows_affected())
        };

        let _rows_affected = self.with_retry("store-request-batch", batch_insert).await?;

        Ok(())
    }

    /// Returns the number of unique requests observed per RP whose `expires_at` falls in
    /// `epoch_span` (an epoch's own `[start, end)` span — NOT its voting window, which opens only
    /// after the epoch has closed), ascending by `rp_id` (as required by `submitBillingVotes`).
    ///
    /// A request's nonce is only guaranteed unique within the epoch it was submitted for, so the
    /// same nonce can show up more than once in `epoch_span` (e.g. a retried submission); `COUNT
    /// (DISTINCT nonce)` collapses those duplicates down to a single count per `rp_id` before
    /// they're reported.
    pub(crate) async fn rp_counts_for_epoch_span(
        &self,
        epoch_span: &Range<u64>,
    ) -> Result<Vec<RpCount>> {
        let query = || async {
            Ok(sqlx::query_as::<_, (i64, i64)>(
                "
                SELECT rp_id, COUNT(DISTINCT nonce) FROM rp_signatures
                WHERE expires_at >= $1 AND expires_at < $2
                GROUP BY rp_id
                ORDER BY rp_id
            ",
            )
            .bind(epoch_span.start as i64)
            .bind(epoch_span.end as i64)
            .fetch_all(&self.pool)
            .await?)
        };
        let rows = self.with_retry("rp-counts-for-epoch-span", query).await?;
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use secrecy::SecretString;
    use taceo_nodes_common::{
        postgres::PostgresConfig,
        test_utils::{next_test_schema, shared_postgres_testcontainer},
    };
    use world_id_primitives::rp::RpId;

    use super::PostgresDb;
    use crate::{accountant_service::RpCount, api::BillableRpRequest};

    /// Builds a [`PostgresDb`] backed by a fresh Postgres schema in the shared testcontainer.
    async fn setup_db() -> PostgresDb {
        let connection_string = shared_postgres_testcontainer()
            .await
            .expect("shared postgres testcontainer starts");
        let mut db_config = PostgresConfig::with_default_values(
            SecretString::from(connection_string.to_owned()),
            next_test_schema(),
        );
        db_config.max_connections = NonZeroU32::new(1).expect("non-zero");
        PostgresDb::init(&db_config)
            .await
            .expect("postgres db initializes")
    }

    fn request(rp_id: u64, nonce: u64, expires_at: u64) -> BillableRpRequest {
        BillableRpRequest {
            rp_id: RpId::new(rp_id),
            nonce: ark_babyjubjub::Fq::from(nonce),
            created_at: expires_at,
            expires_at,
            action: ark_babyjubjub::Fq::from(0u64),
            signature: None,
            wip101_data: None,
        }
    }

    #[tokio::test]
    async fn counts_are_empty_when_no_requests_recorded() {
        let db = setup_db().await;

        let counts = db
            .rp_counts_for_epoch_span(&(1000..1100))
            .await
            .expect("computes counts");

        assert_eq!(counts, vec![]);
    }

    #[tokio::test]
    async fn counts_aggregate_recorded_requests_by_rp_id_within_the_window() {
        let db = setup_db().await;

        // requests for two different windows, to check that each window's counts only include
        // its own requests.
        db.store_request_batch(vec![
            request(5, 1, 1010),
            request(5, 2, 1020),
            request(7, 3, 1030),
            request(9, 4, 1150),
        ])
        .await
        .expect("requests are recorded");

        let window0 = db
            .rp_counts_for_epoch_span(&(1000..1100))
            .await
            .expect("computes counts");
        assert_eq!(
            window0,
            vec![RpCount { rpId: 5, count: 2 }, RpCount { rpId: 7, count: 1 }]
        );

        let window1 = db
            .rp_counts_for_epoch_span(&(1100..1200))
            .await
            .expect("computes counts");
        assert_eq!(window1, vec![RpCount { rpId: 9, count: 1 }]);
    }

    #[tokio::test]
    async fn duplicate_nonces_within_a_window_count_once() {
        let db = setup_db().await;

        // rp 13's nonce 99 is used twice within the same window [1000, 1100) — the second is a
        // replay and must not be double-counted — and once more in a different window
        // [1100, 1200), where reusing the same (rp_id, nonce) pair is fine since uniqueness is
        // only enforced per voting window.
        db.store_request_batch(vec![
            request(13, 99, 1010),
            request(13, 99, 1020),
            request(13, 99, 1150),
        ])
        .await
        .expect("requests are recorded");

        let window0 = db
            .rp_counts_for_epoch_span(&(1000..1100))
            .await
            .expect("computes counts");
        assert_eq!(window0, vec![RpCount { rpId: 13, count: 1 }]);

        let window1 = db
            .rp_counts_for_epoch_span(&(1100..1200))
            .await
            .expect("computes counts");
        assert_eq!(window1, vec![RpCount { rpId: 13, count: 1 }]);
    }

    #[tokio::test]
    async fn duplicate_nonce_with_a_different_expiry_in_the_same_window_still_counts_once() {
        let db = setup_db().await;

        // same (rp_id, nonce) pair, but not literal duplicate rows: the retry carries a
        // different `expires_at` that still falls in the same window. Dedup must key on
        // `nonce` alone, not on the full row.
        db.store_request_batch(vec![request(21, 7, 1010), request(21, 7, 1090)])
            .await
            .expect("requests are recorded");

        let window0 = db
            .rp_counts_for_epoch_span(&(1000..1100))
            .await
            .expect("computes counts");
        assert_eq!(window0, vec![RpCount { rpId: 21, count: 1 }]);
    }

    #[tokio::test]
    async fn same_nonce_reused_across_different_rps_counts_independently() {
        let db = setup_db().await;

        // rp 1 and rp 2 both happen to use nonce 42 in the same window; the dedup is scoped
        // per rp_id, so both should still count.
        db.store_request_batch(vec![request(1, 42, 1010), request(2, 42, 1020)])
            .await
            .expect("requests are recorded");

        let window0 = db
            .rp_counts_for_epoch_span(&(1000..1100))
            .await
            .expect("computes counts");
        assert_eq!(
            window0,
            vec![RpCount { rpId: 1, count: 1 }, RpCount { rpId: 2, count: 1 }]
        );
    }

    #[tokio::test]
    async fn window_is_half_open_on_expires_at() {
        let db = setup_db().await;

        // exactly at the window's start (included) and exactly at its end (excluded, belongs
        // to the next window instead).
        db.store_request_batch(vec![request(1, 1, 1000), request(1, 2, 1100)])
            .await
            .expect("requests are recorded");

        let window0 = db
            .rp_counts_for_epoch_span(&(1000..1100))
            .await
            .expect("computes counts");
        assert_eq!(window0, vec![RpCount { rpId: 1, count: 1 }]);

        let window1 = db
            .rp_counts_for_epoch_span(&(1100..1200))
            .await
            .expect("computes counts");
        assert_eq!(window1, vec![RpCount { rpId: 1, count: 1 }]);
    }

    #[tokio::test]
    async fn results_are_ordered_by_rp_id_regardless_of_insertion_order() {
        let db = setup_db().await;

        // inserted in descending rp_id order, to make sure the ordering comes from the query
        // and not from insertion order.
        db.store_request_batch(vec![
            request(9, 1, 1010),
            request(5, 2, 1020),
            request(7, 3, 1030),
        ])
        .await
        .expect("requests are recorded");

        let window0 = db
            .rp_counts_for_epoch_span(&(1000..1100))
            .await
            .expect("computes counts");
        assert_eq!(
            window0,
            vec![
                RpCount { rpId: 5, count: 1 },
                RpCount { rpId: 7, count: 1 },
                RpCount { rpId: 9, count: 1 },
            ]
        );
    }
}
