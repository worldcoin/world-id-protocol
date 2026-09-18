//! Durable per-wallet transaction leases.
//!
//! The gateway must never sign a second transaction from a wallet while an
//! earlier one is still outstanding: two transactions sharing a nonce collide,
//! and a dropped transaction leaves a nonce gap that stalls every later
//! transaction from that wallet.
//!
//! This module is the persisted form of that rule. One record per wallet
//! address holds either an in-progress lease ([`WalletState::Signing`]), a
//! signed transaction whose fate is not yet known ([`WalletState::InFlight`]),
//! or the same plus an admission that the fate could not be decided
//! ([`WalletState::Parked`]). A wallet is reusable only when its record is
//! gone, so the record must be deleted by an explicit, guarded transition.
//!
//! The record intentionally stores the signed transaction bytes. Without them a
//! process that died between signing and broadcasting can only wait for a
//! timeout and then guess; with them the resolver can re-send byte-identical
//! input and converge.
//!
//! This is the only Redis key family the wallet mechanism adds, so a gateway
//! build that predates it ignores these keys entirely.

use std::time::Duration;

use alloy::primitives::{Address, Bytes, TxHash};
use redis::{Client, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{batch_type::BatchType, error::GatewayResult};

/// Schema version written into every record.
///
/// Forward-compatibility metadata only: reads deliberately do not validate it, so
/// that a build which predates a new field can still decode a newer record. Any
/// reader that depends on a field must therefore treat it as optional.
const SCHEMA_VERSION: u8 = 1;

/// Outcome of a compare-and-set write against a wallet record.
///
/// The counterpart of [`crate::storage::request_store::StatusWriteOutcome`], with
/// the opposite sentinel convention: here `0` means the record is missing and any
/// other non-`1` value is a guard conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CasOutcome {
    /// The write was applied.
    Applied,
    /// No record exists for the wallet.
    Missing,
    /// The record no longer matched what the caller had read, so nothing was written.
    Conflict,
}

impl CasOutcome {
    /// Maps the integer convention used by the Lua scripts.
    ///
    /// `1` is applied, `0` is missing, and any other value is a conflict.
    const fn from_lua(value: i64) -> Self {
        match value {
            1 => Self::Applied,
            0 => Self::Missing,
            _ => Self::Conflict,
        }
    }
}

/// Lifecycle state of a wallet record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WalletState {
    /// A lease is held while the batch is signed. Nothing has been broadcast,
    /// so letting this expire is safe.
    Signing,
    /// A signed transaction is outstanding.
    InFlight,
    /// The transaction's fate could not be decided within the resolution
    /// timeout. The wallet is out of service until it resolves or an operator
    /// clears the record.
    Parked,
}

impl WalletState {
    /// Serialized form, used as the compare-and-set guard value.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Signing => "signing",
            Self::InFlight => "in_flight",
            Self::Parked => "parked",
        }
    }
}

/// Transaction fields recorded from the moment a batch is signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Submission {
    /// Nonce encoded in the signed transaction.
    pub(crate) nonce: u64,
    /// Hash computed locally from the signed bytes.
    pub(crate) tx_hash: TxHash,
    /// EIP-2718 signed bytes, so an ambiguous broadcast can be retried with
    /// identical input. `None` only on a record rebuilt by the lost-record
    /// recovery path, which therefore cannot re-broadcast.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) raw_tx: Option<Bytes>,
    /// Requests that this transaction resolves.
    pub(crate) request_ids: Vec<String>,
    /// Which batch stream submitted it.
    pub(crate) batch_type: BatchType,
    /// Unix seconds at which the record was committed.
    pub(crate) submitted_at: u64,
    /// Unix seconds of the most recent broadcast attempt.
    pub(crate) last_attempt_at: u64,
    /// Number of broadcast attempts made so far.
    pub(crate) attempts: u32,
}

/// The durable record for one wallet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WalletRecord {
    /// Schema version.
    pub(crate) v: u8,
    /// Current lifecycle state.
    pub(crate) state: WalletState,
    /// Identity of the lease that owns the record.
    pub(crate) lease_id: Uuid,
    /// Signed transaction fields, absent only while [`WalletState::Signing`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) submission: Option<Submission>,
}

impl WalletRecord {
    /// A freshly acquired lease, before anything has been signed.
    pub(crate) fn signing(lease_id: Uuid) -> Self {
        Self {
            v: SCHEMA_VERSION,
            state: WalletState::Signing,
            lease_id,
            submission: None,
        }
    }

    /// A wallet whose signed transaction is outstanding.
    pub(crate) fn in_flight(lease_id: Uuid, submission: Submission) -> Self {
        Self {
            v: SCHEMA_VERSION,
            state: WalletState::InFlight,
            lease_id,
            submission: Some(submission),
        }
    }

    /// A wallet whose transaction fate could not be decided.
    pub(crate) fn parked(lease_id: Uuid, submission: Submission) -> Self {
        Self {
            v: SCHEMA_VERSION,
            state: WalletState::Parked,
            lease_id,
            submission: Some(submission),
        }
    }

    /// The signed transaction fields, if the record has been signed.
    pub(crate) fn submission(&self) -> Option<&Submission> {
        self.submission.as_ref()
    }
}

/// Redis storage for wallet leases.
#[derive(Clone)]
pub(crate) struct WalletStore {
    manager: ConnectionManager,
}

impl WalletStore {
    /// Connects to Redis and creates a cloneable connection manager.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is invalid or the initial connection
    /// cannot be established.
    pub(crate) async fn connect(redis_url: &str) -> GatewayResult<Self> {
        let client = Client::open(redis_url)?;
        let manager = ConnectionManager::new(client).await?;
        Ok(Self { manager })
    }

    /// Reserves `wallet` for `lease_id` when no record exists.
    ///
    /// The lease expires after `lease`, which bounds only the signing phase:
    /// nothing has been broadcast yet, so expiry is safe. Returns `false`
    /// without changing storage when the wallet already has a record.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or the Redis call fails.
    pub(crate) async fn reserve(
        &self,
        wallet: Address,
        lease_id: Uuid,
        lease: Duration,
    ) -> GatewayResult<bool> {
        let value = serde_json::to_string(&WalletRecord::signing(lease_id))?;
        let mut manager = self.manager.clone();
        let inserted: Option<String> = redis::cmd("SET")
            .arg(Self::key(wallet))
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(lease.as_secs())
            .query_async(&mut manager)
            .await?;
        Ok(inserted.is_some())
    }

    /// Transitions a record from [`WalletState::Signing`] to
    /// [`WalletState::InFlight`], replacing the lease TTL with `state_ttl`.
    ///
    /// This is the write-ahead commit: it must succeed before the transaction is
    /// broadcast. A conflict means the lease was lost, so the caller must
    /// discard the signature rather than broadcast it.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or the Redis call fails.
    pub(crate) async fn mark_in_flight(
        &self,
        wallet: Address,
        lease_id: Uuid,
        submission: Submission,
        state_ttl: Duration,
    ) -> GatewayResult<CasOutcome> {
        let value = serde_json::to_string(&WalletRecord::in_flight(lease_id, submission))?;
        let mut manager = self.manager.clone();
        let outcome: i64 = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return 0
            end

            local decoded = cjson.decode(current)
            if decoded.state ~= 'signing' or decoded.lease_id ~= ARGV[1] then
                return -1
            end

            redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
            return 1
            "#,
        )
        .key(Self::key(wallet))
        .arg(lease_id.to_string())
        .arg(value)
        .arg(state_ttl.as_secs())
        .invoke_async(&mut manager)
        .await?;
        Ok(CasOutcome::from_lua(outcome))
    }

    /// Replaces a record, guarded by `lease_id`, by `expected_state`, and, when
    /// supplied, by `expected_last_attempt_at`.
    ///
    /// The state guard is what stops a resolver pass acting on a snapshot that
    /// has since been parked: without it, an in-flight replacement would rewrite
    /// a parked record and re-broadcast a transaction whose requests were already
    /// failed. The attempt guard keeps concurrent resolvers from each
    /// incrementing `attempts` and from issuing duplicate re-broadcasts: only the
    /// pass that read the current `last_attempt_at` may write the next one.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or the Redis call fails.
    pub(crate) async fn replace(
        &self,
        wallet: Address,
        lease_id: Uuid,
        expected_state: WalletState,
        expected_last_attempt_at: Option<u64>,
        next: &WalletRecord,
        ttl: Duration,
    ) -> GatewayResult<CasOutcome> {
        debug_assert_eq!(
            next.lease_id, lease_id,
            "replacement must keep the lease identity it is guarded by"
        );
        let value = serde_json::to_string(next)?;
        let expected_attempt = expected_last_attempt_at
            .map_or_else(|| "-1".to_string(), |attempt| attempt.to_string());
        let mut manager = self.manager.clone();
        let outcome: i64 = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return 0
            end

            local decoded = cjson.decode(current)
            if decoded.lease_id ~= ARGV[1] or decoded.state ~= ARGV[2] then
                return -1
            end

            local expected = tonumber(ARGV[3])
            if expected >= 0 then
                local attempt = decoded.submission and tonumber(decoded.submission.last_attempt_at)
                if attempt == nil or attempt ~= expected then
                    return -1
                end
            end

            redis.call('SET', KEYS[1], ARGV[3], 'EX', ARGV[4])
            return 1
            "#,
        )
        .key(Self::key(wallet))
        .arg(lease_id.to_string())
        .arg(expected_state.as_str())
        .arg(expected_attempt)
        .arg(value)
        .arg(ttl.as_secs())
        .invoke_async(&mut manager)
        .await?;
        Ok(CasOutcome::from_lua(outcome))
    }

    /// Deletes a record that is still owned by `lease_id`.
    ///
    /// # Errors
    ///
    /// Returns an error when the Redis call fails.
    pub(crate) async fn release(
        &self,
        wallet: Address,
        lease_id: Uuid,
    ) -> GatewayResult<CasOutcome> {
        let mut manager = self.manager.clone();
        let outcome: i64 = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return 0
            end

            local decoded = cjson.decode(current)
            if decoded.lease_id ~= ARGV[1] then
                return -1
            end

            redis.call('DEL', KEYS[1])
            return 1
            "#,
        )
        .key(Self::key(wallet))
        .arg(lease_id.to_string())
        .invoke_async(&mut manager)
        .await?;
        Ok(CasOutcome::from_lua(outcome))
    }

    /// Extends a record's TTL while it is still owned by `lease_id`.
    ///
    /// Used by the resolver so that records outlive the transaction they
    /// describe. Records whose owner has changed are left untouched.
    ///
    /// # Errors
    ///
    /// Returns an error when the Redis call fails.
    pub(crate) async fn touch(
        &self,
        wallet: Address,
        lease_id: Uuid,
        ttl: Duration,
    ) -> GatewayResult<CasOutcome> {
        let mut manager = self.manager.clone();
        let outcome: i64 = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return 0
            end

            local decoded = cjson.decode(current)
            if decoded.lease_id ~= ARGV[1] then
                return -1
            end

            redis.call('EXPIRE', KEYS[1], ARGV[2])
            return 1
            "#,
        )
        .key(Self::key(wallet))
        .arg(lease_id.to_string())
        .arg(ttl.as_secs())
        .invoke_async(&mut manager)
        .await?;
        Ok(CasOutcome::from_lua(outcome))
    }

    /// Loads one wallet record.
    ///
    /// # Errors
    ///
    /// Returns an error when the Redis call fails or the stored value is not a
    /// valid record.
    pub(crate) async fn get(&self, wallet: Address) -> GatewayResult<Option<WalletRecord>> {
        let mut manager = self.manager.clone();
        let value: Option<String> = redis::cmd("GET")
            .arg(Self::key(wallet))
            .query_async(&mut manager)
            .await?;
        value
            .map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    /// Loads several wallet records in one round trip.
    ///
    /// Results preserve the order of `wallets`. A record that has been corrupted
    /// or written by an incompatible build is reported as `None` and logged,
    /// matching how malformed request records are handled elsewhere.
    ///
    /// # Errors
    ///
    /// Returns an error when the Redis call fails.
    pub(crate) async fn get_many(
        &self,
        wallets: &[Address],
    ) -> GatewayResult<Vec<Option<WalletRecord>>> {
        if wallets.is_empty() {
            return Ok(Vec::new());
        }

        let keys: Vec<String> = wallets.iter().copied().map(Self::key).collect();
        let mut manager = self.manager.clone();
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(keys)
            .query_async(&mut manager)
            .await?;

        Ok(values
            .into_iter()
            .map(|value| {
                value.and_then(|value| {
                    serde_json::from_str(&value)
                        .map_err(|error| {
                            tracing::error!(%error, "failed to deserialize wallet record");
                        })
                        .ok()
                })
            })
            .collect())
    }

    /// Redis key holding one wallet's record.
    fn key(wallet: Address) -> String {
        format!("gateway:wallet:{wallet}")
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use testcontainers_modules::{
        redis::{REDIS_PORT, Redis},
        testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
    };

    use super::*;

    const LEASE: Duration = Duration::from_secs(30);
    const STATE_TTL: Duration = Duration::from_secs(86_400);

    async fn store() -> (WalletStore, ContainerAsync<Redis>) {
        let container = Redis::default()
            .with_tag("latest")
            .start()
            .await
            .expect("failed to start Redis container");
        let host = container
            .get_host()
            .await
            .expect("failed to get Redis host");
        let port = container
            .get_host_port_ipv4(REDIS_PORT)
            .await
            .expect("failed to get Redis port");
        let store = WalletStore::connect(&format!("redis://{host}:{port}"))
            .await
            .expect("failed to connect");
        (store, container)
    }

    fn submission(attempts: u32, last_attempt_at: u64) -> Submission {
        Submission {
            nonce: 7,
            tx_hash: TxHash::repeat_byte(0x11),
            raw_tx: Some(Bytes::from(vec![0x02, 0x01, 0x02])),
            request_ids: vec!["request-1".to_string()],
            batch_type: BatchType::Ops,
            submitted_at: 1_737_000_000,
            last_attempt_at,
            attempts,
        }
    }

    async fn ttl_secs(store: &WalletStore, wallet: Address) -> i64 {
        let mut manager = store.manager.clone();
        redis::cmd("TTL")
            .arg(WalletStore::key(wallet))
            .query_async(&mut manager)
            .await
            .expect("TTL query")
    }

    #[tokio::test]
    async fn reserve_is_exclusive_and_uses_the_signing_lease() {
        let (store, _redis) = store().await;
        let wallet = address!("1111111111111111111111111111111111111111");
        let lease_id = Uuid::new_v4();

        assert!(
            store.reserve(wallet, lease_id, LEASE).await.unwrap(),
            "first reservation succeeds"
        );
        assert!(
            !store.reserve(wallet, Uuid::new_v4(), LEASE).await.unwrap(),
            "a busy wallet cannot be reserved twice"
        );

        let ttl = ttl_secs(&store, wallet).await;
        assert!(
            ttl > 0 && ttl <= LEASE.as_secs().cast_signed(),
            "signing lease TTL is bounded, got {ttl}"
        );

        let record = store.get(wallet).await.unwrap().expect("record exists");
        assert_eq!(record.state, WalletState::Signing);
        assert_eq!(record.lease_id, lease_id);
        assert!(record.submission().is_none());
    }

    #[tokio::test]
    async fn mark_in_flight_requires_the_signing_lease() {
        let (store, _redis) = store().await;
        let wallet = address!("2222222222222222222222222222222222222222");
        let lease_id = Uuid::new_v4();
        store.reserve(wallet, lease_id, LEASE).await.unwrap();

        // A lease that no longer owns the record cannot commit a transaction.
        assert_eq!(
            store
                .mark_in_flight(wallet, Uuid::new_v4(), submission(0, 10), STATE_TTL)
                .await
                .unwrap(),
            CasOutcome::Conflict,
        );

        assert_eq!(
            store
                .mark_in_flight(wallet, lease_id, submission(0, 10), STATE_TTL)
                .await
                .unwrap(),
            CasOutcome::Applied,
        );

        let ttl = ttl_secs(&store, wallet).await;
        assert!(
            ttl > LEASE.as_secs().cast_signed(),
            "committing replaces the signing lease with the state TTL, got {ttl}"
        );

        // A committed record is no longer signing, so it cannot commit twice.
        assert_eq!(
            store
                .mark_in_flight(wallet, lease_id, submission(0, 11), STATE_TTL)
                .await
                .unwrap(),
            CasOutcome::Conflict,
        );
    }

    #[tokio::test]
    async fn replace_is_guarded_by_the_attempt_counter() {
        let (store, _redis) = store().await;
        let wallet = address!("3333333333333333333333333333333333333333");
        let lease_id = Uuid::new_v4();
        store.reserve(wallet, lease_id, LEASE).await.unwrap();
        store
            .mark_in_flight(wallet, lease_id, submission(0, 10), STATE_TTL)
            .await
            .unwrap();

        let next = submission(1, 20);

        // A stale attempt value must not be able to advance the record.
        assert_eq!(
            store
                .replace(
                    wallet,
                    lease_id,
                    WalletState::InFlight,
                    Some(9),
                    &WalletRecord::in_flight(lease_id, next.clone()),
                    STATE_TTL
                )
                .await
                .unwrap(),
            CasOutcome::Conflict,
        );

        assert_eq!(
            store
                .replace(
                    wallet,
                    lease_id,
                    WalletState::InFlight,
                    Some(10),
                    &WalletRecord::in_flight(lease_id, next),
                    STATE_TTL
                )
                .await
                .unwrap(),
            CasOutcome::Applied,
        );

        let record = store.get(wallet).await.unwrap().expect("record exists");
        assert_eq!(record.submission().unwrap().attempts, 1);
        assert_eq!(record.submission().unwrap().last_attempt_at, 20);
    }

    #[tokio::test]
    async fn release_is_guarded_and_reports_a_missing_record() {
        let (store, _redis) = store().await;
        let wallet = address!("4444444444444444444444444444444444444444");
        let lease_id = Uuid::new_v4();

        assert_eq!(
            store.release(wallet, lease_id).await.unwrap(),
            CasOutcome::Missing
        );

        store.reserve(wallet, lease_id, LEASE).await.unwrap();

        // A different holder cannot release someone else's lease.
        assert_eq!(
            store.release(wallet, Uuid::new_v4()).await.unwrap(),
            CasOutcome::Conflict
        );
        assert!(store.get(wallet).await.unwrap().is_some());

        assert_eq!(
            store.release(wallet, lease_id).await.unwrap(),
            CasOutcome::Applied
        );
        assert!(store.get(wallet).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn parked_records_keep_their_signed_bytes() {
        let (store, _redis) = store().await;
        let wallet = address!("5555555555555555555555555555555555555555");
        let lease_id = Uuid::new_v4();
        store.reserve(wallet, lease_id, LEASE).await.unwrap();
        let submission = submission(3, 30);
        store
            .mark_in_flight(wallet, lease_id, submission.clone(), STATE_TTL)
            .await
            .unwrap();

        assert_eq!(
            store
                .replace(
                    wallet,
                    lease_id,
                    WalletState::InFlight,
                    Some(30),
                    &WalletRecord::parked(lease_id, submission.clone()),
                    STATE_TTL
                )
                .await
                .unwrap(),
            CasOutcome::Applied,
        );

        let record = store.get(wallet).await.unwrap().expect("record exists");
        assert_eq!(record.state, WalletState::Parked);
        assert_eq!(record.submission().unwrap().tx_hash, submission.tx_hash);
        assert_eq!(
            record.submission().unwrap().raw_tx,
            submission.raw_tx,
            "parked records keep the signed bytes so the fate can still be probed"
        );
    }

    #[tokio::test]
    async fn touch_only_extends_records_the_lease_still_owns() {
        let (store, _redis) = store().await;
        let wallet = address!("6666666666666666666666666666666666666666");
        let lease_id = Uuid::new_v4();
        store.reserve(wallet, lease_id, LEASE).await.unwrap();
        store
            .mark_in_flight(wallet, lease_id, submission(0, 40), STATE_TTL)
            .await
            .unwrap();

        // Shorten the TTL so a successful touch is observable.
        store
            .replace(
                wallet,
                lease_id,
                WalletState::InFlight,
                Some(40),
                &WalletRecord::in_flight(lease_id, submission(0, 41)),
                Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .touch(wallet, Uuid::new_v4(), Duration::from_secs(1000))
                .await
                .unwrap(),
            CasOutcome::Conflict,
        );
        assert!(
            ttl_secs(&store, wallet).await <= 5,
            "a foreign holder cannot extend the TTL"
        );

        assert_eq!(
            store
                .touch(wallet, lease_id, Duration::from_secs(1000))
                .await
                .unwrap(),
            CasOutcome::Applied,
        );
        assert!(ttl_secs(&store, wallet).await > 5);
    }

    #[tokio::test]
    async fn get_many_preserves_order_and_reports_missing_records() {
        let (store, _redis) = store().await;
        let first = address!("7777777777777777777777777777777777777777");
        let second = address!("8888888888888888888888888888888888888888");

        assert!(store.get_many(&[]).await.unwrap().is_empty());

        store.reserve(second, Uuid::new_v4(), LEASE).await.unwrap();

        let records = store.get_many(&[first, second]).await.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records[0].is_none());
        assert!(records[1].is_some());
    }

    #[test]
    fn record_serializes_with_a_state_discriminator() {
        let record = WalletRecord::signing(Uuid::nil());
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"state\":\"signing\""), "got {json}");
        assert_eq!(serde_json::from_str::<WalletRecord>(&json).unwrap(), record);
    }

    #[test]
    fn cas_outcome_maps_the_lua_convention() {
        assert_eq!(CasOutcome::from_lua(1), CasOutcome::Applied);
        assert_eq!(CasOutcome::from_lua(0), CasOutcome::Missing);
        assert_eq!(CasOutcome::from_lua(-1), CasOutcome::Conflict);
    }
}
