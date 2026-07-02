//! Request Tracking (WIP-107 Request Storage)
//!
//! This module persists authenticated RP requests to a Postgres database so
//! that they can later be counted per RP and epoch for billing (see WIP-107).
//! It stores every field the RP signs over plus the signature itself, so the
//! signature of a recorded request can be re-verified at any time.
//!
//! Tracking is fully asynchronous and MUST NOT add latency or failure points
//! to the OPRF hot path: [`RequestTracker::track`] pushes into a bounded
//! in-memory channel and never blocks. A background writer task drains the
//! channel and batch-inserts into Postgres with bounded, jittered
//! exponential-backoff retries. If the channel is full or the database stays
//! unavailable past the retry budget, records are dropped and the drops are
//! surfaced via metrics ([`crate::metrics::request_tracking`]) — the OPRF
//! request itself is never affected.
//!
//! No counting or read access is implemented yet. The table layout and the
//! `(rp_id, expiration_timestamp, nonce)` index are chosen so that the
//! epoch-based distinct-nonce counting from WIP-107 (epoch assignment by
//! `expiration_timestamp`, dedup on `nonce`) can be added as a query later.

use std::{num::NonZeroUsize, time::Duration};

use ark_ff::{BigInteger as _, PrimeField as _};
use backon::{BackoffBuilder as _, ExponentialBuilder, Retryable as _};
use eyre::Context as _;
use sqlx::PgPool;
use taceo_nodes_common::postgres::{CreateSchema, PostgresConfig, pg_pool_with_schema};
use taceo_oprf::types::api::OprfRequest;
use tokio::sync::mpsc;
use world_id_primitives::{oprf::NullifierOprfRequestAuthV1, rp::RpId};

use crate::{auth::rp_module::RpModuleKind, metrics};

/// Idempotent DDL executed on start-up.
///
/// We deliberately use `IF NOT EXISTS` DDL instead of `sqlx::migrate!`: the
/// configured schema may be shared with other services (e.g. the OPRF key-gen
/// secret manager) whose sqlx migration bookkeeping table would conflict.
const INIT_DDL: &str = r"
CREATE TABLE IF NOT EXISTS rp_requests (
    id bigserial PRIMARY KEY,
    -- u64 RP id stored with a lossless wrapping cast to bigint
    rp_id bigint NOT NULL,
    -- OPRF module that authenticated the request ('uniqueness' or 'session')
    module text NOT NULL,
    -- 32-byte big-endian field elements
    action bytea NOT NULL,
    nonce bytea NOT NULL,
    -- RP-signed unix timestamps (secs)
    current_time_stamp bigint NOT NULL,
    expiration_timestamp bigint NOT NULL,
    -- 65-byte ECDSA signature; NULL for WIP-101 contract-verified requests
    signature bytea,
    -- auxiliary data sent to WIP-101 signer contracts
    wip101_data bytea,
    -- node-local receive time, for pruning and audits
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rp_requests_rp_expiration_nonce
    ON rp_requests (rp_id, expiration_timestamp, nonce);
";

/// Configuration for [`RequestTracker`].
#[derive(Clone, Debug, serde::Deserialize)]
#[non_exhaustive]
pub struct RequestTrackingConfig {
    /// Postgres connection config for the request-tracking database.
    pub postgres: PostgresConfig,
    /// Capacity of the in-memory queue between the auth hot path and the
    /// database writer. When full, new records are dropped (and counted in
    /// metrics) instead of blocking request handling.
    #[serde(default = "RequestTrackingConfig::default_channel_capacity")]
    pub channel_capacity: NonZeroUsize,
    /// Maximum number of records written per `INSERT` batch.
    #[serde(default = "RequestTrackingConfig::default_max_batch_size")]
    pub max_batch_size: NonZeroUsize,
    /// Maximum number of retries for a failed batch insert before the batch
    /// is dropped (surfaced via metrics).
    #[serde(default = "RequestTrackingConfig::default_insert_max_retries")]
    pub insert_max_retries: usize,
    /// Minimum delay of the jittered exponential backoff between insert retries.
    #[serde(
        default = "RequestTrackingConfig::default_insert_retry_min_delay",
        with = "humantime_serde"
    )]
    pub insert_retry_min_delay: Duration,
    /// Maximum delay of the jittered exponential backoff between insert retries.
    #[serde(
        default = "RequestTrackingConfig::default_insert_retry_max_delay",
        with = "humantime_serde"
    )]
    pub insert_retry_max_delay: Duration,
}

impl RequestTrackingConfig {
    fn default_channel_capacity() -> NonZeroUsize {
        NonZeroUsize::new(4096).expect("4096 is non-zero")
    }

    fn default_max_batch_size() -> NonZeroUsize {
        NonZeroUsize::new(128).expect("128 is non-zero")
    }

    const fn default_insert_max_retries() -> usize {
        5
    }

    const fn default_insert_retry_min_delay() -> Duration {
        Duration::from_millis(100)
    }

    const fn default_insert_retry_max_delay() -> Duration {
        Duration::from_secs(5)
    }

    /// Initialize with default values for all optional fields.
    #[must_use]
    pub fn with_default_values(postgres: PostgresConfig) -> Self {
        Self {
            postgres,
            channel_capacity: Self::default_channel_capacity(),
            max_batch_size: Self::default_max_batch_size(),
            insert_max_retries: Self::default_insert_max_retries(),
            insert_retry_min_delay: Self::default_insert_retry_min_delay(),
            insert_retry_max_delay: Self::default_insert_retry_max_delay(),
        }
    }
}

/// A single authenticated RP request as persisted to the request storage.
///
/// Contains all fields the RP signs over (see
/// [`world_id_primitives::rp::compute_rp_signature_msg`]) plus the signature,
/// so the record's authenticity can be re-verified later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrackedRequest {
    pub(crate) rp_id: RpId,
    pub(crate) module: RpModuleKind,
    pub(crate) action: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) current_time_stamp: u64,
    pub(crate) expiration_timestamp: u64,
    pub(crate) signature: Option<Vec<u8>>,
    pub(crate) wip101_data: Option<Vec<u8>>,
}

impl TrackedRequest {
    /// Extracts the fields to persist from an authenticated OPRF request.
    pub(crate) fn from_request(
        module: RpModuleKind,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Self {
        let to_be_32 = |fe: &ark_babyjubjub::Fq| -> [u8; 32] {
            let bytes = fe.into_bigint().to_bytes_be();
            let mut out = [0u8; 32];
            out[32 - bytes.len()..].copy_from_slice(&bytes);
            out
        };
        Self {
            rp_id: request.auth.rp_id,
            module,
            action: to_be_32(&request.auth.action),
            nonce: to_be_32(&request.auth.nonce),
            current_time_stamp: request.auth.current_time_stamp,
            expiration_timestamp: request.auth.expiration_timestamp,
            signature: request
                .auth
                .signature
                .map(|sig| sig.as_bytes().to_vec()),
            wip101_data: request.auth.wip101_data.clone(),
        }
    }
}

impl RpModuleKind {
    /// Stable string identifier used in the `module` database column.
    const fn as_db_str(self) -> &'static str {
        match self {
            RpModuleKind::Uniqueness => "uniqueness",
            RpModuleKind::Session => "session",
        }
    }
}

/// Handle to the request-tracking writer.
///
/// Cloning is cheap; all clones feed the same background writer task. The
/// writer task shuts down gracefully (draining remaining records) once every
/// handle has been dropped.
#[derive(Clone)]
pub(crate) struct RequestTracker {
    sender: mpsc::Sender<TrackedRequest>,
}

impl RequestTracker {
    /// Connects to Postgres, creates the storage table if needed, and spawns
    /// the background writer task.
    ///
    /// # Errors
    /// Returns an error if the database is unreachable or the DDL fails. This
    /// is a start-up-only failure mode: once initialized, database outages
    /// degrade to dropped tracking records instead of errors.
    pub(crate) async fn init(config: &RequestTrackingConfig) -> eyre::Result<Self> {
        let pool = pg_pool_with_schema(&config.postgres, CreateSchema::Yes)
            .await
            .context("while connecting to request-tracking postgres")?;

        sqlx::raw_sql(INIT_DDL)
            .execute(&pool)
            .await
            .context("while creating request-tracking table")?;

        let (sender, receiver) = mpsc::channel(config.channel_capacity.get());

        tokio::spawn(write_loop(
            pool,
            receiver,
            config.max_batch_size.get(),
            backoff_builder(config),
        ));

        Ok(Self { sender })
    }

    /// Enqueues a request record for persistence. Never blocks.
    ///
    /// If the queue is full (writer overloaded or database unavailable), the
    /// record is dropped and counted in the drop metric — request handling is
    /// deliberately unaffected.
    pub(crate) fn track(&self, request: TrackedRequest) {
        metrics::request_tracking::inc_tracked(request.module.as_db_str());
        if let Err(err) = self.sender.try_send(request) {
            metrics::request_tracking::inc_dropped(
                metrics::request_tracking::DROP_REASON_QUEUE_FULL,
                1,
            );
            tracing::warn!("dropping request-tracking record: {err}");
        }
    }
}

fn backoff_builder(config: &RequestTrackingConfig) -> ExponentialBuilder {
    ExponentialBuilder::new()
        .with_min_delay(config.insert_retry_min_delay)
        .with_max_delay(config.insert_retry_max_delay)
        .with_max_times(config.insert_max_retries)
        .with_jitter()
}

/// Drains the channel and batch-inserts records until all senders are dropped.
async fn write_loop(
    pool: PgPool,
    mut receiver: mpsc::Receiver<TrackedRequest>,
    max_batch_size: usize,
    backoff: ExponentialBuilder,
) {
    let mut batch = Vec::with_capacity(max_batch_size);
    while receiver.recv_many(&mut batch, max_batch_size).await > 0 {
        let insert = || insert_batch(&pool, &batch);
        let result = insert
            .retry(backoff.build())
            .notify(|err, delay| {
                tracing::warn!(?delay, "retrying request-tracking insert: {err}");
            })
            .await;
        if let Err(err) = result {
            metrics::request_tracking::inc_dropped(
                metrics::request_tracking::DROP_REASON_DB_ERROR,
                batch.len() as u64,
            );
            tracing::error!(
                batch_size = batch.len(),
                "dropping request-tracking batch after retries: {err}"
            );
        }
        batch.clear();
    }
    tracing::info!("request-tracking writer shutting down");
}

/// Inserts a batch of records with a single multi-row `INSERT` via `UNNEST`.
async fn insert_batch(pool: &PgPool, batch: &[TrackedRequest]) -> Result<(), sqlx::Error> {
    let mut rp_ids = Vec::with_capacity(batch.len());
    let mut modules = Vec::with_capacity(batch.len());
    let mut actions = Vec::with_capacity(batch.len());
    let mut nonces = Vec::with_capacity(batch.len());
    let mut current_time_stamps = Vec::with_capacity(batch.len());
    let mut expiration_timestamps = Vec::with_capacity(batch.len());
    let mut signatures: Vec<Option<Vec<u8>>> = Vec::with_capacity(batch.len());
    let mut wip101_datas: Vec<Option<Vec<u8>>> = Vec::with_capacity(batch.len());

    for record in batch {
        // lossless wrapping casts; readers reverse with `as u64`
        #[expect(clippy::cast_possible_wrap, reason = "lossless wrapping u64->i64")]
        rp_ids.push(record.rp_id.into_inner() as i64);
        modules.push(record.module.as_db_str());
        actions.push(record.action.as_slice());
        nonces.push(record.nonce.as_slice());
        #[expect(clippy::cast_possible_wrap, reason = "lossless wrapping u64->i64")]
        current_time_stamps.push(record.current_time_stamp as i64);
        #[expect(clippy::cast_possible_wrap, reason = "lossless wrapping u64->i64")]
        expiration_timestamps.push(record.expiration_timestamp as i64);
        signatures.push(record.signature.clone());
        wip101_datas.push(record.wip101_data.clone());
    }

    sqlx::query(
        r"
        INSERT INTO rp_requests
            (rp_id, module, action, nonce, current_time_stamp, expiration_timestamp, signature, wip101_data)
        SELECT * FROM UNNEST
            ($1::bigint[], $2::text[], $3::bytea[], $4::bytea[], $5::bigint[], $6::bigint[], $7::bytea[], $8::bytea[])
        ",
    )
    .bind(&rp_ids)
    .bind(&modules)
    .bind(&actions)
    .bind(&nonces)
    .bind(&current_time_stamps)
    .bind(&expiration_timestamps)
    .bind(&signatures)
    .bind(&wip101_datas)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use secrecy::SecretString;
    use sqlx::Row as _;
    use taceo_nodes_common::postgres::SanitizedSchema;

    use super::*;

    /// Connection string of the Postgres instance provided by the repo's
    /// `docker-compose.yml` (also used by the indexer tests).
    fn test_connection_string() -> SecretString {
        std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".to_owned())
            .into()
    }

    /// Builds a config pointing at a uniquely-named schema so tests are
    /// isolated from each other.
    fn test_config(schema: &str) -> RequestTrackingConfig {
        let schema = SanitizedSchema::from_str(schema).expect("valid schema name");
        let mut config = RequestTrackingConfig::with_default_values(
            PostgresConfig::with_default_values(test_connection_string(), schema),
        );
        config.insert_retry_min_delay = Duration::from_millis(10);
        config.insert_retry_max_delay = Duration::from_millis(50);
        config
    }

    fn test_record(rp_id: u64, nonce_byte: u8) -> TrackedRequest {
        TrackedRequest {
            rp_id: RpId::new(rp_id),
            module: RpModuleKind::Uniqueness,
            action: [0u8; 32],
            nonce: [nonce_byte; 32],
            current_time_stamp: 1_000,
            expiration_timestamp: 2_000,
            signature: Some(vec![0xab; 65]),
            wip101_data: None,
        }
    }

    async fn count_rows(pool: &PgPool) -> i64 {
        sqlx::query("SELECT count(*) FROM rp_requests")
            .fetch_one(pool)
            .await
            .expect("can count rows")
            .get(0)
    }

    /// Polls until `expected` rows are present or the timeout is reached.
    async fn wait_for_rows(pool: &PgPool, expected: i64) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if count_rows(pool).await == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("rows should be persisted before timeout");
    }

    #[tokio::test]
    async fn test_tracked_requests_are_persisted() -> eyre::Result<()> {
        let config = test_config("request_tracking_test_persist");
        let pool = pg_pool_with_schema(&config.postgres, CreateSchema::Yes).await?;
        sqlx::raw_sql("DROP TABLE IF EXISTS rp_requests")
            .execute(&pool)
            .await?;

        let tracker = RequestTracker::init(&config).await?;
        tracker.track(test_record(42, 1));
        tracker.track(test_record(42, 2));
        tracker.track(test_record(7, 3));
        wait_for_rows(&pool, 3).await;

        let row = sqlx::query(
            "SELECT module, action, nonce, current_time_stamp, expiration_timestamp, signature, wip101_data
             FROM rp_requests WHERE rp_id = $1 AND nonce = $2",
        )
        .bind(7i64)
        .bind([3u8; 32].as_slice())
        .fetch_one(&pool)
        .await?;
        assert_eq!(row.get::<String, _>("module"), "uniqueness", "module kind");
        assert_eq!(row.get::<Vec<u8>, _>("action"), vec![0u8; 32], "action");
        assert_eq!(
            row.get::<i64, _>("current_time_stamp"),
            1_000,
            "current_time_stamp"
        );
        assert_eq!(
            row.get::<i64, _>("expiration_timestamp"),
            2_000,
            "expiration_timestamp"
        );
        assert_eq!(
            row.get::<Option<Vec<u8>>, _>("signature"),
            Some(vec![0xab; 65]),
            "signature"
        );
        assert_eq!(
            row.get::<Option<Vec<u8>>, _>("wip101_data"),
            None,
            "wip101_data"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_init_is_idempotent() -> eyre::Result<()> {
        let config = test_config("request_tracking_test_idempotent");
        let pool = pg_pool_with_schema(&config.postgres, CreateSchema::Yes).await?;
        sqlx::raw_sql("DROP TABLE IF EXISTS rp_requests")
            .execute(&pool)
            .await?;

        // A second init against the same schema must not fail or wipe data.
        let first = RequestTracker::init(&config).await?;
        first.track(test_record(1, 1));
        wait_for_rows(&pool, 1).await;

        let second = RequestTracker::init(&config).await?;
        second.track(test_record(1, 2));
        wait_for_rows(&pool, 2).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_writer_drains_on_shutdown() -> eyre::Result<()> {
        let config = test_config("request_tracking_test_drain");
        let pool = pg_pool_with_schema(&config.postgres, CreateSchema::Yes).await?;
        sqlx::raw_sql("DROP TABLE IF EXISTS rp_requests")
            .execute(&pool)
            .await?;

        let tracker = RequestTracker::init(&config).await?;
        for i in 0..100u8 {
            tracker.track(test_record(1, i));
        }
        // Dropping the last handle closes the channel; the writer must still
        // drain everything that was enqueued.
        drop(tracker);
        wait_for_rows(&pool, 100).await;
        Ok(())
    }
}
