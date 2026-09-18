#![cfg(feature = "integration-tests")]

use std::time::Duration;

use alloy::primitives::Address;
use redis::{AsyncCommands, aio::ConnectionManager};
use testcontainers_modules::{redis::Redis, testcontainers::ContainerAsync};
use world_id_gateway::{
    OrphanSweeperConfig, RequestRecord, RequestTracker, now_unix_secs,
    request_tracker::BacklogScope, sweep_once,
};
use world_id_primitives::api_types::{GatewayRequestKind, GatewayRequestState};

async fn setup_redis(redis_url: &str) -> ConnectionManager {
    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    client.get_connection_manager().await.unwrap()
}

async fn setup_isolated_redis_for_test() -> (String, ContainerAsync<Redis>, ConnectionManager) {
    let (container, url) = world_id_test_utils::redis_testcontainer()
        .await
        .expect("failed to start Redis testcontainer");
    let redis = setup_redis(&url).await;
    (url, container, redis)
}

fn assert_age_in_range(actual: u64, expected_min: u64) {
    let expected_max = expected_min + 5;
    assert!(
        actual >= expected_min && actual <= expected_max,
        "age out of range: actual={actual}, expected_min={expected_min}, expected_max={expected_max}"
    );
}

/// Insert a request record directly into Redis with a specific state and timestamp.
async fn inject_request(
    redis: &mut ConnectionManager,
    id: &str,
    kind: GatewayRequestKind,
    status: GatewayRequestState,
    updated_at: u64,
) {
    inject_request_with_wallet(redis, id, kind, status, updated_at, None).await;
}

/// Insert a request record that claims a signing wallet.
async fn inject_request_with_wallet(
    redis: &mut ConnectionManager,
    id: &str,
    kind: GatewayRequestKind,
    status: GatewayRequestState,
    updated_at: u64,
    wallet: Option<Address>,
) {
    let record = RequestRecord {
        kind,
        status,
        updated_at,
        inflight_keys: Vec::new(),
        wallet,
    };
    let key = format!("gateway:request:{id}");
    let json = serde_json::to_string(&record).unwrap();
    let _: () = redis.set_ex(&key, &json, 86_400).await.unwrap();
    let _: () = redis.sadd("gateway:pending_requests", id).await.unwrap();
}

/// Insert only a set member (no corresponding request key).
async fn inject_dangling_set_member(redis: &mut ConnectionManager, id: &str) {
    let _: () = redis.sadd("gateway:pending_requests", id).await.unwrap();
}

/// Builds a tracker with a fixed in-flight lock lifetime, so individual tests
/// do not have to care about it.
async fn tracker(redis_url: &str) -> RequestTracker {
    RequestTracker::new(redis_url.to_string(), None, Duration::from_secs(300)).await
}

/// Read request record from Redis.
async fn read_record(redis: &mut ConnectionManager, id: &str) -> Option<RequestRecord> {
    let key = format!("gateway:request:{id}");
    let result: Option<String> = redis.get(&key).await.unwrap();
    result.map(|s| serde_json::from_str(&s).unwrap())
}

/// Check if an ID is in the pending set.
async fn is_in_pending_set(redis: &mut ConnectionManager, id: &str) -> bool {
    let result: bool = redis
        .sismember("gateway:pending_requests", id)
        .await
        .unwrap();
    result
}

// =========================================================================
// RequestTracker unit-level tests (Redis only)
// =========================================================================

/// Verifies that creating a request adds it to the pending set, and
/// transitioning to `Finalized` atomically removes it.
#[tokio::test]
async fn pending_set_lifecycle_finalized() {
    let (url, _redis_container, _redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;
    let id = "test-pending-lifecycle-fin".to_string();

    tracker
        .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount, Vec::new())
        .await
        .unwrap();

    let pending = tracker.get_pending_requests().await.unwrap();
    assert!(
        pending.contains(&id),
        "new request should be in pending set"
    );

    tracker
        .set_status(
            &id,
            GatewayRequestState::Finalized {
                tx_hash: "0xabc".to_string(),
            },
        )
        .await;

    let pending = tracker.get_pending_requests().await.unwrap();
    assert!(
        !pending.contains(&id),
        "finalized request should be removed from pending set"
    );
}

/// Verifies that failing a request also removes it from the pending set.
#[tokio::test]
async fn pending_set_lifecycle_failed() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;
    let id = "test-pending-lifecycle-fail".to_string();

    tracker
        .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount, Vec::new())
        .await
        .unwrap();

    assert!(is_in_pending_set(&mut redis, &id).await);

    tracker
        .set_status(&id, GatewayRequestState::failed("test error", None))
        .await;

    assert!(!is_in_pending_set(&mut redis, &id).await);
}

/// Verifies that `updated_at` is set on creation and bumped on status
/// changes. This timestamp drives staleness calculations in the sweeper.
#[tokio::test]
async fn updated_at_written_and_updated() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;
    let id = "test-updated-at".to_string();
    let before = now_unix_secs();

    tracker
        .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount, Vec::new())
        .await
        .unwrap();

    let record = read_record(&mut redis, &id).await.unwrap();
    let created_at = record.updated_at;
    assert!(created_at >= before);

    tokio::time::sleep(Duration::from_secs(1)).await;

    tracker
        .set_status(
            &id,
            GatewayRequestState::Submitted {
                tx_hash: "0xdef".to_string(),
            },
        )
        .await;

    let record = read_record(&mut redis, &id).await.unwrap();
    assert!(record.updated_at > created_at);
}

/// Verifies that `snapshot_batch` (MGET) returns records for existing keys
/// and `None` for missing keys, preserving input order.
#[tokio::test]
async fn snapshot_batch_returns_records() {
    let (url, _redis_container, _redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    tracker
        .new_request_with_id(
            "batch-1".to_string(),
            GatewayRequestKind::CreateAccount,
            Vec::new(),
        )
        .await
        .unwrap();
    tracker
        .new_request_with_id(
            "batch-2".to_string(),
            GatewayRequestKind::UpdateAuthenticator,
            Vec::new(),
        )
        .await
        .unwrap();

    let results = tracker
        .snapshot_batch(&[
            "batch-1".to_string(),
            "batch-2".to_string(),
            "nonexistent".to_string(),
        ])
        .await
        .unwrap();

    assert_eq!(results.len(), 3);
    assert!(results[0].1.is_some());
    assert!(results[1].1.is_some());
    assert!(results[2].1.is_none());
}

/// Verifies queued backlog stats only consider `Queued` requests and use
/// `updated_at` age for urgency calculations.
#[tokio::test]
async fn queued_backlog_stats_from_updated_at() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;

    let tracker = tracker(&url).await;
    let now = now_unix_secs();

    inject_request(
        &mut redis,
        "queued-10s",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        now - 10,
    )
    .await;
    inject_request(
        &mut redis,
        "queued-20s",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        now - 20,
    )
    .await;
    inject_request(
        &mut redis,
        "queued-30s",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        now - 30,
    )
    .await;
    inject_request(
        &mut redis,
        "batching-40s",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Batching,
        now - 40,
    )
    .await;

    let stats = tracker.queued_backlog_stats().await.unwrap();
    assert_eq!(stats.queued_count, 3);
    assert_age_in_range(stats.oldest_age_secs, 30);
}

/// Verifies backlog urgency stats are isolated by batcher scope (`Create` vs `Ops`).
#[tokio::test]
async fn queued_backlog_stats_scoped_by_kind() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;

    let tracker = tracker(&url).await;
    let now = now_unix_secs();

    // create backlog
    inject_request(
        &mut redis,
        "create-10s",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        now - 10,
    )
    .await;

    // ops backlog
    inject_request(
        &mut redis,
        "ops-update-40s",
        GatewayRequestKind::UpdateAuthenticator,
        GatewayRequestState::Queued,
        now - 40,
    )
    .await;
    inject_request(
        &mut redis,
        "ops-remove-20s",
        GatewayRequestKind::RemoveAuthenticator,
        GatewayRequestState::Queued,
        now - 20,
    )
    .await;

    let create_stats = tracker
        .queued_backlog_stats_for_scope(BacklogScope::Create)
        .await
        .unwrap();
    assert_eq!(create_stats.queued_count, 1);
    assert_age_in_range(create_stats.oldest_age_secs, 10);

    let ops_stats = tracker
        .queued_backlog_stats_for_scope(BacklogScope::Ops)
        .await
        .unwrap();
    assert_eq!(ops_stats.queued_count, 2);
    assert_age_in_range(ops_stats.oldest_age_secs, 40);

    let all_stats = tracker
        .queued_backlog_stats_for_scope(BacklogScope::All)
        .await
        .unwrap();
    assert_eq!(all_stats.queued_count, 3);
    assert_age_in_range(all_stats.oldest_age_secs, 40);
}

// =========================================================================
// Sweeper integration tests (Redis + Anvil)
// =========================================================================

/// Verifies that a `Queued` request older than the staleness threshold is
/// marked as `Failed` with an "orphaned" error and removed from the pending set.
#[tokio::test]
async fn sweep_stale_queued_request() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;
    let five_min_ago = now_unix_secs() - 300;

    inject_request(
        &mut redis,
        "stale-queued",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        five_min_ago,
    )
    .await;

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &config).await;

    let record = read_record(&mut redis, "stale-queued").await.unwrap();
    match &record.status {
        GatewayRequestState::Failed { error, .. } => {
            assert!(error.contains("timed out in queued state"));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(!is_in_pending_set(&mut redis, "stale-queued").await);
}

/// Verifies that a recently-created `Queued` request is left alone by the
/// sweeper. Ensures the sweeper only acts on stale requests.
#[tokio::test]
async fn sweep_fresh_queued_untouched() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    inject_request(
        &mut redis,
        "fresh-queued",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        now_unix_secs(),
    )
    .await;

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &config).await;

    let record = read_record(&mut redis, "fresh-queued").await.unwrap();
    assert!(matches!(record.status, GatewayRequestState::Queued));
    assert!(is_in_pending_set(&mut redis, "fresh-queued").await);
}

/// Verifies that a `Batching` request older than the queued threshold is
/// marked as `Failed`. Batching and Queued share the same staleness logic.
#[tokio::test]
async fn sweep_stale_batching_request() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;
    let five_min_ago = now_unix_secs() - 300;

    inject_request(
        &mut redis,
        "stale-batching",
        GatewayRequestKind::InsertAuthenticator,
        GatewayRequestState::Batching,
        five_min_ago,
    )
    .await;

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &config).await;

    let record = read_record(&mut redis, "stale-batching").await.unwrap();
    assert!(matches!(record.status, GatewayRequestState::Failed { .. }));
    assert!(!is_in_pending_set(&mut redis, "stale-batching").await);
}

/// Verifies that a pending set entry with no corresponding request record
/// in Redis is cleaned up (e.g. the record expired or was never written).
#[tokio::test]
async fn sweep_dangling_set_member() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    inject_dangling_set_member(&mut redis, "dangling-id").await;
    assert!(is_in_pending_set(&mut redis, "dangling-id").await);

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &config).await;

    assert!(
        !is_in_pending_set(&mut redis, "dangling-id").await,
        "dangling set member should be removed"
    );
}

/// Verifies that a `Finalized` request left in the pending set gets cleaned
/// out without changing its status. A safety-net for inconsistent state.
#[tokio::test]
async fn sweep_already_terminal_in_set() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    inject_request(
        &mut redis,
        "already-finalized",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Finalized {
            tx_hash: "0xabc".to_string(),
        },
        now_unix_secs(),
    )
    .await;

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &config).await;

    assert!(
        !is_in_pending_set(&mut redis, "already-finalized").await,
        "terminal request should be cleaned from pending set"
    );
    let record = read_record(&mut redis, "already-finalized").await.unwrap();
    assert!(
        matches!(record.status, GatewayRequestState::Finalized { .. }),
        "status should remain unchanged"
    );
}

/// Verifies that a submission owned by a wallet record is left alone by the
/// sweeper, however old it is: the transaction resolver owns it and has the
/// signed bytes needed to decide its fate.
#[tokio::test]
async fn sweep_leaves_wallet_owned_submission_untouched() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    inject_request_with_wallet(
        &mut redis,
        "owned-submitted",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Submitted {
            tx_hash: "0x11".to_string(),
        },
        now_unix_secs() - 3_600,
        Some(Address::repeat_byte(0x11)),
    )
    .await;

    let config = OrphanSweeperConfig {
        stale_submitted_threshold_secs: 60,
        ..Default::default()
    };
    sweep_once(&tracker, &config).await;

    let record = read_record(&mut redis, "owned-submitted").await.unwrap();
    assert!(
        matches!(record.status, GatewayRequestState::Submitted { .. }),
        "a wallet-owned submission belongs to the resolver, not the sweeper"
    );
    assert!(is_in_pending_set(&mut redis, "owned-submitted").await);
}

/// Verifies that a submission with no wallet, written by a gateway build that
/// predates wallet leases, is still failed once stale. Nothing else can resolve
/// it, and the class disappears as those records expire.
#[tokio::test]
async fn sweep_fails_legacy_submission_without_wallet() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    inject_request(
        &mut redis,
        "legacy-submitted",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Submitted {
            tx_hash: "0x22".to_string(),
        },
        now_unix_secs() - 300,
    )
    .await;

    let config = OrphanSweeperConfig {
        stale_submitted_threshold_secs: 120,
        ..Default::default()
    };
    sweep_once(&tracker, &config).await;

    let record = read_record(&mut redis, "legacy-submitted").await.unwrap();
    assert!(
        matches!(record.status, GatewayRequestState::Failed { .. }),
        "a submission nobody can resolve must not stay pending forever"
    );
    assert!(!is_in_pending_set(&mut redis, "legacy-submitted").await);
}

/// A fresh legacy submission is left alone: it may still be in a mempool.
#[tokio::test]
async fn sweep_leaves_fresh_legacy_submission_untouched() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    inject_request(
        &mut redis,
        "fresh-legacy-submitted",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Submitted {
            tx_hash: "0x33".to_string(),
        },
        now_unix_secs(),
    )
    .await;

    sweep_once(&tracker, &OrphanSweeperConfig::default()).await;

    let record = read_record(&mut redis, "fresh-legacy-submitted")
        .await
        .unwrap();
    assert!(matches!(
        record.status,
        GatewayRequestState::Submitted { .. }
    ));
    assert!(is_in_pending_set(&mut redis, "fresh-legacy-submitted").await);
}

/// The sweeper must never overwrite a status another owner already advanced.
/// It writes through a guard that only accepts `Queued` and `Batching`, so a
/// stale snapshot cannot turn a `Submitted` request into a failure.
#[tokio::test]
async fn sweep_cannot_overwrite_a_resolved_request() {
    let (url, _redis_container, mut redis) = setup_isolated_redis_for_test().await;
    let tracker = tracker(&url).await;

    inject_request(
        &mut redis,
        "already-finalized-stale",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Finalized {
            tx_hash: "0x44".to_string(),
        },
        now_unix_secs() - 3_600,
    )
    .await;

    sweep_once(&tracker, &OrphanSweeperConfig::default()).await;

    let record = read_record(&mut redis, "already-finalized-stale")
        .await
        .unwrap();
    assert!(
        matches!(record.status, GatewayRequestState::Finalized { .. }),
        "a terminal status must survive a stale sweeper pass"
    );
}
