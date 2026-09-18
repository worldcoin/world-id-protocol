use std::{collections::HashSet, time::Duration};

use alloy::primitives::Address;
use redis::{AsyncTypedCommands, Client, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use world_id_primitives::api_types::{GatewayRequestKind, GatewayRequestState};

use crate::error::GatewayResult;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRecord {
    pub kind: GatewayRequestKind,
    pub status: GatewayRequestState,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inflight_keys: Vec<String>,
    /// Wallet that signed the transaction resolving this request, when known.
    ///
    /// Additive: records written before this field existed deserialize with
    /// `None`, which is how the lost-wallet-record recovery path tells legacy
    /// requests apart. The transaction hash is not duplicated here because it
    /// already appears in [`GatewayRequestState::Submitted`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub wallet: Option<Address>,
}

const REQUESTS_TTL: Duration = Duration::from_secs(86_400);
const PENDING_SET_KEY: &str = "gateway:pending_requests";

/// Discriminator of a stored [`GatewayRequestState`], used to guard a
/// compare-and-set status write.
///
/// The names match the serialized `status.state` values so the guard can be
/// evaluated inside the Lua script without a second representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusGuard {
    Queued,
    Batching,
    Submitted,
}

impl StatusGuard {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Batching => "batching",
            Self::Submitted => "submitted",
        }
    }
}

/// Result of a compare-and-set status write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusWriteOutcome {
    /// The write was applied.
    Applied,
    /// The stored status was not one of the allowed values, so nothing was written.
    Guarded,
    /// The request record does not exist, which for an expired record is terminal.
    Missing,
}

/// Result of atomically creating a tracked request and acquiring its locks.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CreateRequestOutcome {
    /// The request record, pending-set entry, and in-flight locks were created.
    Created,
    /// An in-flight lock already existed, so nothing was created.
    DuplicateInflight(String),
}

/// Result of checking and recording a request against a rate-limit window.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RateLimitOutcome {
    /// The request was recorded; the value is the current count in the window.
    Allowed(u64),
    /// The request was not recorded because the configured limit was reached.
    Exceeded,
}

/// Persistent storage for gateway request tracking.
///
/// This module owns the Redis schema, commands, scripts, TTLs, and JSON
/// serialization. Callers operate on request-tracking concepts only.
#[derive(Clone)]
pub(crate) struct RequestStore {
    manager: ConnectionManager,
    /// Lifetime of an in-flight lock. Must outlive the request it protects, or
    /// duplicate detection lapses while the request is still being submitted.
    inflight_ttl: Duration,
}

impl RequestStore {
    /// Connects to Redis and creates a cloneable connection manager.
    ///
    /// `inflight_ttl` bounds how long a request's in-flight lock survives; see
    /// [`Self::inflight_ttl`].
    ///
    /// # Panics
    ///
    /// Panics if `redis_url` is invalid or the initial connection cannot be
    /// established.
    pub(crate) async fn connect(redis_url: &str, inflight_ttl: Duration) -> Self {
        let client = Client::open(redis_url).expect("Unable to connect to Redis");
        let manager = ConnectionManager::new(client)
            .await
            .expect("Unable to create Redis connection manager");

        tracing::info!("Connection to Redis established");
        Self {
            manager,
            inflight_ttl,
        }
    }

    /// Stores a terminal request record without adding pending or in-flight entries.
    ///
    /// The record expires after [`REQUESTS_TTL`]. If `id` already exists, the
    /// existing record is preserved.
    pub(crate) async fn create_terminal_request(
        &self,
        id: &str,
        kind: GatewayRequestKind,
        status: GatewayRequestState,
        updated_at: u64,
    ) -> GatewayResult<()> {
        let record = RequestRecord {
            kind,
            status,
            updated_at,
            inflight_keys: Vec::new(),
            wallet: None,
        };
        let json = serde_json::to_string(&record)?;
        let mut manager = self.manager.clone();

        let _: () = redis::cmd("SET")
            .arg(Self::request_key(id))
            .arg(json)
            .arg("NX")
            .arg("EX")
            .arg(REQUESTS_TTL.as_secs())
            .query_async(&mut manager)
            .await?;
        Ok(())
    }

    /// Atomically creates a queued request, pending entry, and in-flight locks.
    ///
    /// Returns [`CreateRequestOutcome::DuplicateInflight`] without changing
    /// storage when any requested lock already exists. Each lock stores the
    /// owning request ID. The request record uses [`REQUESTS_TTL`], while lock
    /// entries use [`INFLIGHT_TTL`].
    pub(crate) async fn create_request(
        &self,
        id: &str,
        kind: GatewayRequestKind,
        inflight_keys: &[String],
        updated_at: u64,
    ) -> GatewayResult<CreateRequestOutcome> {
        let redis_inflight_keys: Vec<String> = inflight_keys
            .iter()
            .map(|raw| Self::inflight_key(kind, raw))
            .collect();

        // TODO: Consider using HSET to set fields of this struct individually
        let record = RequestRecord {
            kind,
            status: GatewayRequestState::Queued,
            updated_at,
            inflight_keys: redis_inflight_keys.clone(),
            wallet: None,
        };
        let json = serde_json::to_string(&record)?;
        let mut manager = self.manager.clone();

        let script = redis::Script::new(
            r#"
            local request_key = KEYS[1]
            local pending_set_key = KEYS[2]
            local inflight_keys = { unpack(KEYS, 3) }

            local payload = ARGV[1]
            local requests_ttl = tonumber(ARGV[2])
            local request_id = ARGV[3]
            local inflight_ttl = tonumber(ARGV[4])

            for _, inflight_key in ipairs(inflight_keys) do
                if redis.call('EXISTS', inflight_key) == 1 then
                    return inflight_key
                end
            end

            for _, inflight_key in ipairs(inflight_keys) do
                redis.call('SET', inflight_key, request_id, 'EX', inflight_ttl)
            end

            local ok = redis.call('SET', request_key, payload, 'NX', 'EX', requests_ttl)
            if not ok then
                for _, inflight_key in ipairs(inflight_keys) do
                    if redis.call('GET', inflight_key) == request_id then
                        redis.call('DEL', inflight_key)
                    end
                end
                return redis.error_reply('request already exists')
            end

            redis.call('SADD', pending_set_key, request_id)
            return nil
            "#,
        );
        let mut invocation = script.prepare_invoke();
        invocation.key(Self::request_key(id));
        invocation.key(PENDING_SET_KEY);
        for key in &redis_inflight_keys {
            invocation.key(key);
        }
        invocation.arg(json);
        invocation.arg(REQUESTS_TTL.as_secs());
        invocation.arg(id);
        invocation.arg(self.inflight_ttl.as_secs());

        let duplicate: Option<String> = invocation.invoke_async(&mut manager).await?;
        Ok(match duplicate {
            Some(key) => CreateRequestOutcome::DuplicateInflight(key),
            None => CreateRequestOutcome::Created,
        })
    }

    /// Loads and deserializes one request record by ID.
    ///
    /// Returns `Ok(None)` when the record does not exist.
    pub(crate) async fn request(&self, id: &str) -> GatewayResult<Option<RequestRecord>> {
        let mut manager = self.manager.clone();
        let json: Option<String> = manager.get(Self::request_key(id)).await?;
        json.map(|json| serde_json::from_str(&json).map_err(Into::into))
            .transpose()
    }

    /// Atomically updates a request's status and timestamp while preserving its TTL.
    ///
    /// Terminal statuses also remove the request from the pending set and delete
    /// its in-flight locks. Returns an error when the request does not exist.
    pub(crate) async fn update_status(
        &self,
        id: &str,
        status: &GatewayRequestState,
        updated_at: u64,
    ) -> GatewayResult<()> {
        let status_json = serde_json::to_string(status)?;
        let mut manager = self.manager.clone();

        let _: () = redis::Script::new(
            r#"
            local request_key = KEYS[1]
            local pending_set_key = KEYS[2]

            local status = ARGV[1]
            local updated_at = tonumber(ARGV[2])
            local request_id = ARGV[3]

            local record = redis.call('GET', request_key)
            if not record then
                return redis.error_reply('attempted to update inexistent request')
            end

            local decoded = cjson.decode(record)
            decoded.status = cjson.decode(status)
            decoded.updated_at = updated_at
            local updated = cjson.encode(decoded)

            redis.call('SET', request_key, updated, 'KEEPTTL')

            local state = decoded.status.state
            if state == 'finalized' or state == 'failed' then
                redis.call('SREM', pending_set_key, request_id)
                local inflight = decoded.inflight_keys
                if inflight then
                    for _, k in ipairs(inflight) do
                        local owner = redis.call('GET', k)
                        -- Gateway versions predating lock ownership stored literal 1.
                        if owner == request_id or owner == '1' then
                            redis.call('DEL', k)
                        end
                    end
                end
            end

            return redis.status_reply('OK')
            "#,
        )
        .key(Self::request_key(id))
        .key(PENDING_SET_KEY)
        .arg(status_json)
        .arg(updated_at)
        .arg(id)
        .invoke_async(&mut manager)
        .await?;
        Ok(())
    }

    /// Atomically applies a status only while the stored status is one of
    /// `allowed`, preserving the record's TTL.
    ///
    /// This is the guard that keeps two independent owners from clobbering each
    /// other: the orphan sweeper may only move a request out of
    /// `Queued`/`Batching`, and the resolver may only move it out of
    /// `Batching`/`Submitted`. Without the guard, a sweeper reading a stale
    /// snapshot can overwrite a status another task has already advanced,
    /// reporting a request as failed while its transaction is on chain.
    ///
    /// `wallet` is written when supplied and left untouched when `None`, so a
    /// legacy record is never given a budget it did not earn.
    ///
    /// Terminal statuses additionally remove the request from the pending set
    /// and delete the in-flight locks it still owns, matching
    /// [`Self::update_status`].
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or the Redis call fails.
    pub(crate) async fn update_status_if(
        &self,
        id: &str,
        allowed: &[StatusGuard],
        status: &GatewayRequestState,
        updated_at: u64,
        wallet: Option<Address>,
    ) -> GatewayResult<StatusWriteOutcome> {
        let allowed_json = Self::status_guard_json(allowed)?;
        let status_json = serde_json::to_string(status)?;
        let wallet = wallet.map_or_else(String::new, |wallet| wallet.to_string());

        let mut manager = self.manager.clone();
        let outcome: i64 = redis::Script::new(
            r#"
            local request_key = KEYS[1]
            local pending_set_key = KEYS[2]

            local allowed = cjson.decode(ARGV[1])
            local status = ARGV[2]
            local updated_at = tonumber(ARGV[3])
            local request_id = ARGV[4]
            local wallet = ARGV[5]

            local record = redis.call('GET', request_key)
            if not record then
                return -1
            end

            local decoded = cjson.decode(record)
            local current = decoded.status.state
            local accepted = false
            for _, name in ipairs(allowed) do
                if current == name then
                    accepted = true
                    break
                end
            end
            if not accepted then
                return 0
            end

            decoded.status = cjson.decode(status)
            decoded.updated_at = updated_at
            if wallet ~= '' then
                decoded.wallet = wallet
            end
            redis.call('SET', request_key, cjson.encode(decoded), 'KEEPTTL')

            local state = decoded.status.state
            if state == 'finalized' or state == 'failed' then
                redis.call('SREM', pending_set_key, request_id)
                local inflight = decoded.inflight_keys
                if inflight then
                    for _, key in ipairs(inflight) do
                        local owner = redis.call('GET', key)
                        -- Gateway versions predating lock ownership stored literal 1.
                        if owner == request_id or owner == '1' then
                            redis.call('DEL', key)
                        end
                    end
                end
            end

            return 1
            "#,
        )
        .key(Self::request_key(id))
        .key(PENDING_SET_KEY)
        .arg(allowed_json)
        .arg(status_json)
        .arg(updated_at)
        .arg(id)
        .arg(wallet)
        .invoke_async(&mut manager)
        .await?;

        Ok(Self::status_write_outcome(outcome))
    }

    /// Atomically applies a status to every request in a batch, or to none of
    /// them.
    ///
    /// All-or-nothing matters here: a partially applied transition would leave
    /// some requests recorded as `Submitted` for a transaction the caller is
    /// about to discard, with no wallet record for the resolver to pick up.
    /// Callers treat [`StatusWriteOutcome::Guarded`] as "do not broadcast".
    ///
    /// # Errors
    ///
    /// Returns an error when `ids` is empty, serialization fails, or the Redis
    /// call fails.
    pub(crate) async fn update_status_batch_if(
        &self,
        ids: &[String],
        allowed: &[StatusGuard],
        status: &GatewayRequestState,
        updated_at: u64,
        wallet: Option<Address>,
    ) -> GatewayResult<StatusWriteOutcome> {
        if ids.is_empty() {
            return Ok(StatusWriteOutcome::Missing);
        }

        let allowed_json = Self::status_guard_json(allowed)?;
        let status_json = serde_json::to_string(status)?;
        let wallet = wallet.map_or_else(String::new, |wallet| wallet.to_string());

        let mut manager = self.manager.clone();
        let script = redis::Script::new(
            r#"
            local last = #KEYS
            local pending_set_key = KEYS[last]
            local count = last - 1

            local allowed = cjson.decode(ARGV[1])
            local status = ARGV[2]
            local updated_at = tonumber(ARGV[3])
            local wallet = ARGV[4]

            local decoded_records = {}
            for i = 1, count do
                local record = redis.call('GET', KEYS[i])
                if not record then
                    return -1
                end

                local decoded = cjson.decode(record)
                local current = decoded.status.state
                local accepted = false
                for _, name in ipairs(allowed) do
                    if current == name then
                        accepted = true
                        break
                    end
                end
                if not accepted then
                    return 0
                end

                decoded_records[i] = decoded
            end

            for i = 1, count do
                local decoded = decoded_records[i]
                local request_id = ARGV[i + 4]

                decoded.status = cjson.decode(status)
                decoded.updated_at = updated_at
                if wallet ~= '' then
                    decoded.wallet = wallet
                end
                redis.call('SET', KEYS[i], cjson.encode(decoded), 'KEEPTTL')

                local state = decoded.status.state
                if state == 'finalized' or state == 'failed' then
                    redis.call('SREM', pending_set_key, request_id)
                    local inflight = decoded.inflight_keys
                    if inflight then
                        for _, key in ipairs(inflight) do
                            local owner = redis.call('GET', key)
                            if owner == request_id or owner == '1' then
                                redis.call('DEL', key)
                            end
                        end
                    end
                end
            end

            return 1
            "#,
        );
        let mut invocation = script.prepare_invoke();

        for id in ids {
            invocation.key(Self::request_key(id));
        }
        invocation.key(PENDING_SET_KEY);
        invocation.arg(allowed_json);
        invocation.arg(status_json);
        invocation.arg(updated_at);
        invocation.arg(wallet);
        for id in ids {
            invocation.arg(id);
        }

        let outcome: i64 = invocation.invoke_async(&mut manager).await?;
        Ok(Self::status_write_outcome(outcome))
    }

    /// Serializes a guard list into the JSON array the Lua scripts expect.
    fn status_guard_json(allowed: &[StatusGuard]) -> GatewayResult<String> {
        let names: Vec<&'static str> = allowed.iter().map(|guard| guard.as_str()).collect();
        Ok(serde_json::to_string(&names)?)
    }

    /// Maps the integer convention used by the guarded status scripts.
    const fn status_write_outcome(value: i64) -> StatusWriteOutcome {
        match value {
            1 => StatusWriteOutcome::Applied,
            0 => StatusWriteOutcome::Guarded,
            _ => StatusWriteOutcome::Missing,
        }
    }

    /// Returns every request ID in the pending set.
    ///
    /// The returned order is unspecified.
    pub(crate) async fn pending_request_ids(&self) -> GatewayResult<Vec<String>> {
        let mut manager = self.manager.clone();
        let ids: HashSet<String> = manager.smembers(PENDING_SET_KEY).await?;
        Ok(ids.into_iter().collect())
    }

    /// Loads multiple request records in one Redis round trip.
    ///
    /// Results preserve the order of `ids`. Missing or malformed records are
    /// represented as `None`; malformed records are also logged.
    pub(crate) async fn requests(
        &self,
        ids: &[String],
    ) -> GatewayResult<Vec<(String, Option<RequestRecord>)>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let keys: Vec<String> = ids.iter().map(|id| Self::request_key(id)).collect();
        let mut manager = self.manager.clone();
        let values: Vec<Option<String>> = manager.mget(keys).await?;

        Ok(ids
            .iter()
            .zip(values)
            .map(|(id, json)| {
                let record = json.and_then(|json| {
                    serde_json::from_str(&json)
                        .map_err(|error| {
                            tracing::error!(request_id = id, %error, "Failed to deserialize request from Redis");
                        })
                        .ok()
                });
                (id.clone(), record)
            })
            .collect())
    }

    /// Removes a request ID from the pending set.
    ///
    /// Succeeds when the ID was not present, making cleanup idempotent.
    pub(crate) async fn remove_pending_request(&self, id: &str) -> GatewayResult<()> {
        let mut manager = self.manager.clone();
        let _: usize = manager.srem(PENDING_SET_KEY, id).await?;
        Ok(())
    }

    /// Atomically checks and records a request in a leaf's sliding time window.
    ///
    /// Entries at or before `now - window_secs` are removed before counting.
    /// Allowed requests are inserted with `request_id` as the sorted-set member;
    /// rejected requests do not modify the current window after stale cleanup.
    pub(crate) async fn check_rate_limit(
        &self,
        leaf_index: u64,
        request_id: &str,
        now: u64,
        window_secs: u64,
        max_requests: u64,
    ) -> GatewayResult<RateLimitOutcome> {
        let mut manager = self.manager.clone();
        let count: i64 = redis::Script::new(
            r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local request_id = ARGV[4]

            local min_timestamp = now - window
            redis.call('ZREMRANGEBYSCORE', key, '-inf', min_timestamp)
            local current = redis.call('ZCARD', key)

            if current < limit then
                redis.call('ZADD', key, now, request_id)
                redis.call('EXPIRE', key, window)
                return current + 1
            else
                return -1
            end
            "#,
        )
        .key(Self::rate_limit_key(leaf_index))
        .arg(now)
        .arg(window_secs)
        .arg(max_requests)
        .arg(request_id)
        .invoke_async(&mut manager)
        .await?;

        Ok(if count == -1 {
            RateLimitOutcome::Exceeded
        } else {
            RateLimitOutcome::Allowed(count as u64)
        })
    }

    /// Returns the Redis key containing one serialized request record.
    fn request_key(id: &str) -> String {
        format!("gateway:request:{id}")
    }

    /// Returns the Redis key for an in-flight request lock.
    ///
    /// Account creation locks are scoped by authenticator address; all other
    /// request kinds are scoped by leaf index.
    fn inflight_key(kind: GatewayRequestKind, raw: &str) -> String {
        let tag = match kind {
            GatewayRequestKind::CreateAccount => "create",
            _ => "leaf",
        };
        format!("gateway:inflight:{tag}:{raw}")
    }

    /// Returns the Redis sorted-set key for one leaf's rate-limit window.
    fn rate_limit_key(leaf_index: u64) -> String {
        format!("gateway:ratelimit:leaf:{leaf_index}")
    }
}

#[cfg(test)]
mod tests {
    use redis::AsyncTypedCommands;
    use testcontainers_modules::{
        redis::{REDIS_PORT, Redis},
        testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
    };
    use world_id_primitives::api_types::GatewayErrorCode;

    use super::*;

    async fn store() -> (RequestStore, ContainerAsync<Redis>) {
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
        let store =
            RequestStore::connect(&format!("redis://{host}:{port}"), Duration::from_secs(300))
                .await;
        (store, container)
    }

    #[test]
    fn request_record_serializes_to_expected_json() {
        let record = RequestRecord {
            kind: GatewayRequestKind::CreateAccount,
            status: GatewayRequestState::Queued,
            updated_at: 42,
            inflight_keys: vec!["gateway:inflight:create:0x1234".to_string()],
            wallet: None,
        };

        assert_eq!(
            serde_json::to_string_pretty(&record).unwrap(),
            indoc::indoc! {r#"
                {
                  "kind": "create_account",
                  "status": {
                    "state": "queued"
                  },
                  "updated_at": 42,
                  "inflight_keys": [
                    "gateway:inflight:create:0x1234"
                  ]
                }
            "#}
            .trim()
        );
    }

    #[tokio::test]
    async fn request_lifecycle_is_atomic() {
        let (store, _redis) = store().await;
        let lock = "0x1234".to_string();

        assert_eq!(
            store
                .create_request(
                    "request-1",
                    GatewayRequestKind::CreateAccount,
                    std::slice::from_ref(&lock),
                    10,
                )
                .await
                .unwrap(),
            CreateRequestOutcome::Created
        );
        assert_eq!(
            store.pending_request_ids().await.unwrap(),
            ["request-1".to_string()]
        );

        let record = store.request("request-1").await.unwrap().unwrap();
        assert!(matches!(record.status, GatewayRequestState::Queued));
        assert_eq!(record.updated_at, 10);
        assert_eq!(record.inflight_keys, ["gateway:inflight:create:0x1234"]);

        store
            .update_status("request-1", &GatewayRequestState::Batching, 20)
            .await
            .unwrap();
        assert_eq!(
            store.pending_request_ids().await.unwrap(),
            ["request-1".to_string()]
        );

        store
            .update_status(
                "request-1",
                &GatewayRequestState::Finalized {
                    tx_hash: "0xabc".to_string(),
                },
                30,
            )
            .await
            .unwrap();
        assert!(store.pending_request_ids().await.unwrap().is_empty());

        let mut manager = store.manager.clone();
        let lock_exists: bool = manager
            .exists("gateway:inflight:create:0x1234")
            .await
            .unwrap();
        assert!(!lock_exists);
    }

    #[tokio::test]
    async fn duplicate_lock_does_not_partially_create_request() {
        let (store, _redis) = store().await;
        let shared_lock = "7".to_string();

        store
            .create_request(
                "request-1",
                GatewayRequestKind::UpdateAuthenticator,
                std::slice::from_ref(&shared_lock),
                10,
            )
            .await
            .unwrap();
        let outcome = store
            .create_request(
                "request-2",
                GatewayRequestKind::RemoveAuthenticator,
                std::slice::from_ref(&shared_lock),
                11,
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            CreateRequestOutcome::DuplicateInflight("gateway:inflight:leaf:7".to_string())
        );
        assert!(store.request("request-2").await.unwrap().is_none());
        assert_eq!(
            store.pending_request_ids().await.unwrap(),
            ["request-1".to_string()]
        );
    }

    #[tokio::test]
    async fn terminal_request_releases_legacy_inflight_lock() {
        let (store, _redis) = store().await;
        let lock = "7".to_string();
        let redis_lock = "gateway:inflight:leaf:7";

        store
            .create_request(
                "request-1",
                GatewayRequestKind::UpdateAuthenticator,
                &[lock],
                10,
            )
            .await
            .unwrap();

        // Simulate a lock created by a gateway version that predates lock ownership.
        let mut manager = store.manager.clone();
        let _: () = manager.set(redis_lock, "1").await.unwrap();

        store
            .update_status(
                "request-1",
                &GatewayRequestState::Finalized {
                    tx_hash: "0xabc".to_string(),
                },
                20,
            )
            .await
            .unwrap();

        let lock_exists: bool = manager.exists(redis_lock).await.unwrap();
        assert!(!lock_exists);
    }

    #[tokio::test]
    async fn old_request_does_not_release_reacquired_inflight_lock() {
        let (store, _redis) = store().await;
        let shared_lock = "7".to_string();
        let redis_lock = "gateway:inflight:leaf:7";

        store
            .create_request(
                "request-1",
                GatewayRequestKind::UpdateAuthenticator,
                std::slice::from_ref(&shared_lock),
                10,
            )
            .await
            .unwrap();

        // Simulate request-1's lock expiring without waiting for its TTL.
        let mut manager = store.manager.clone();
        let _: usize = manager.del(redis_lock).await.unwrap();

        store
            .create_request(
                "request-2",
                GatewayRequestKind::UpdateAuthenticator,
                &[shared_lock],
                311,
            )
            .await
            .unwrap();

        store
            .update_status(
                "request-1",
                &GatewayRequestState::Finalized {
                    tx_hash: "0xabc".to_string(),
                },
                312,
            )
            .await
            .unwrap();

        let lock_owner: Option<String> = manager.get(redis_lock).await.unwrap();
        assert_eq!(lock_owner.as_deref(), Some("request-2"));
    }

    #[tokio::test]
    async fn batched_reads_preserve_order_and_missing_entries() {
        let (store, _redis) = store().await;

        store
            .create_terminal_request(
                "request-1",
                GatewayRequestKind::CreateAccount,
                GatewayRequestState::failed("rejected", Some(GatewayErrorCode::BadRequest)),
                10,
            )
            .await
            .unwrap();

        let records = store
            .requests(&["missing".to_string(), "request-1".to_string()])
            .await
            .unwrap();
        assert_eq!(records[0].0, "missing");
        assert!(records[0].1.is_none());
        assert_eq!(records[1].0, "request-1");
        assert!(matches!(
            records[1].1.as_ref().map(|record| &record.status),
            Some(GatewayRequestState::Failed { .. })
        ));
    }

    #[tokio::test]
    async fn rate_limit_window_is_enforced_and_expires_inclusively() {
        let (store, _redis) = store().await;

        assert_eq!(
            store
                .check_rate_limit(7, "request-1", 100, 10, 2)
                .await
                .unwrap(),
            RateLimitOutcome::Allowed(1)
        );
        assert_eq!(
            store
                .check_rate_limit(7, "request-2", 101, 10, 2)
                .await
                .unwrap(),
            RateLimitOutcome::Allowed(2)
        );
        assert_eq!(
            store
                .check_rate_limit(7, "request-3", 102, 10, 2)
                .await
                .unwrap(),
            RateLimitOutcome::Exceeded
        );
        assert_eq!(
            store
                .check_rate_limit(7, "request-4", 110, 10, 2)
                .await
                .unwrap(),
            RateLimitOutcome::Allowed(2)
        );
    }
}
