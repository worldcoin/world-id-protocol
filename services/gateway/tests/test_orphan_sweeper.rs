#![cfg(feature = "integration-tests")]

use std::time::Duration;

use alloy::{
    primitives::{Address, U256, address},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use redis::{AsyncCommands, aio::ConnectionManager};
use reqwest::{Client, StatusCode};
use world_id_core::api_types::{GatewayRequestKind, GatewayRequestState, GatewayStatusResponse};
use world_id_gateway::{
    GatewayConfig, OrphanSweeperConfig, RequestRecord, RequestTracker, now_unix_secs,
    spawn_gateway_for_tests, sweep_once,
};
use world_id_services_common::{ProviderArgs, SignerArgs};
use world_id_test_utils::anvil::TestAnvil;

mod common;
use crate::common::{wait_for_finalized, wait_http_ready};

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async fn setup_redis(redis_url: &str) -> ConnectionManager {
    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    client.get_connection_manager().await.unwrap()
}

async fn flush_redis(redis: &mut ConnectionManager) {
    let _: () = redis::cmd("FLUSHDB").query_async(redis).await.unwrap();
}

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
}

/// Insert a request record directly into Redis with a specific state and timestamp.
async fn inject_request(
    redis: &mut ConnectionManager,
    id: &str,
    kind: GatewayRequestKind,
    status: GatewayRequestState,
    updated_at: u64,
) {
    let record = RequestRecord {
        kind,
        status,
        updated_at,
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
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url, None).await;
    let id = "test-pending-lifecycle-fin".to_string();

    tracker
        .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount)
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
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url, None).await;
    let id = "test-pending-lifecycle-fail".to_string();

    tracker
        .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount)
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
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url, None).await;
    let id = "test-updated-at".to_string();
    let before = now_unix_secs();

    tracker
        .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount)
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
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url, None).await;

    tracker
        .new_request_with_id("batch-1".to_string(), GatewayRequestKind::CreateAccount)
        .await
        .unwrap();
    tracker
        .new_request_with_id(
            "batch-2".to_string(),
            GatewayRequestKind::UpdateAuthenticator,
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

// =========================================================================
// Sweeper integration tests (Redis + Anvil)
// =========================================================================

/// Verifies that a `Queued` request older than the staleness threshold is
/// marked as `Failed` with an "orphaned" error and removed from the pending set.
#[tokio::test]
async fn sweep_stale_queued_request() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url.clone(), None).await;
    let five_min_ago = now_unix_secs() - 300;

    inject_request(
        &mut redis,
        "stale-queued",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        five_min_ago,
    )
    .await;

    let anvil = TestAnvil::spawn().unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &dyn_provider, &config).await;

    let record = read_record(&mut redis, "stale-queued").await.unwrap();
    match &record.status {
        GatewayRequestState::Failed { error, .. } => {
            assert!(error.contains("orphaned"));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(!is_in_pending_set(&mut redis, "stale-queued").await);
}

/// Verifies that a recently-created `Queued` request is left alone by the
/// sweeper. Ensures the sweeper only acts on stale requests.
#[tokio::test]
async fn sweep_fresh_queued_untouched() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url.clone(), None).await;

    inject_request(
        &mut redis,
        "fresh-queued",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Queued,
        now_unix_secs(),
    )
    .await;

    let anvil = TestAnvil::spawn().unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &dyn_provider, &config).await;

    let record = read_record(&mut redis, "fresh-queued").await.unwrap();
    assert!(matches!(record.status, GatewayRequestState::Queued));
    assert!(is_in_pending_set(&mut redis, "fresh-queued").await);
}

/// Verifies that a `Batching` request older than the queued threshold is
/// marked as `Failed`. Batching and Queued share the same staleness logic.
#[tokio::test]
async fn sweep_stale_batching_request() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url.clone(), None).await;
    let five_min_ago = now_unix_secs() - 300;

    inject_request(
        &mut redis,
        "stale-batching",
        GatewayRequestKind::InsertAuthenticator,
        GatewayRequestState::Batching,
        five_min_ago,
    )
    .await;

    let anvil = TestAnvil::spawn().unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &dyn_provider, &config).await;

    let record = read_record(&mut redis, "stale-batching").await.unwrap();
    assert!(matches!(record.status, GatewayRequestState::Failed { .. }));
    assert!(!is_in_pending_set(&mut redis, "stale-batching").await);
}

/// Verifies that a pending set entry with no corresponding request record
/// in Redis is cleaned up (e.g. the record expired or was never written).
#[tokio::test]
async fn sweep_dangling_set_member() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url.clone(), None).await;

    inject_dangling_set_member(&mut redis, "dangling-id").await;
    assert!(is_in_pending_set(&mut redis, "dangling-id").await);

    let anvil = TestAnvil::spawn().unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &dyn_provider, &config).await;

    assert!(
        !is_in_pending_set(&mut redis, "dangling-id").await,
        "dangling set member should be removed"
    );
}

/// Verifies that a `Finalized` request left in the pending set gets cleaned
/// out without changing its status. A safety-net for inconsistent state.
#[tokio::test]
async fn sweep_already_terminal_in_set() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url.clone(), None).await;

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

    let anvil = TestAnvil::spawn().unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &dyn_provider, &config).await;

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

/// Verifies that a `Submitted` request with no on-chain receipt that exceeds
/// the submitted threshold is marked as `Failed`. Covers dropped transactions.
#[tokio::test]
async fn sweep_submitted_no_receipt_stale() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url.clone(), None).await;
    let five_min_ago = now_unix_secs() - 300;

    inject_request(
        &mut redis,
        "stale-submitted",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Submitted {
            tx_hash: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .to_string(),
        },
        five_min_ago,
    )
    .await;

    let anvil = TestAnvil::spawn().unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig {
        stale_submitted_threshold_secs: 120, // 2-minute submitted threshold
        ..Default::default()
    };
    sweep_once(&tracker, &dyn_provider, &config).await;

    let record = read_record(&mut redis, "stale-submitted").await.unwrap();
    match &record.status {
        GatewayRequestState::Failed { error, .. } => {
            assert!(error.contains("not confirmed"));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(!is_in_pending_set(&mut redis, "stale-submitted").await);
}

/// Verifies that a recently-submitted request without a receipt is left
/// alone. The transaction may still be pending in the sequencer's mempool.
#[tokio::test]
async fn sweep_submitted_no_receipt_fresh() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let tracker = RequestTracker::new(url.clone(), None).await;

    inject_request(
        &mut redis,
        "fresh-submitted",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Submitted {
            tx_hash: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .to_string(),
        },
        now_unix_secs(),
    )
    .await;

    let anvil = TestAnvil::spawn().unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &dyn_provider, &config).await;

    let record = read_record(&mut redis, "fresh-submitted").await.unwrap();
    assert!(
        matches!(record.status, GatewayRequestState::Submitted { .. }),
        "fresh submitted request should not be touched"
    );
    assert!(is_in_pending_set(&mut redis, "fresh-submitted").await);
}

/// End-to-end: submits a real transaction, then injects an orphaned request
/// referencing the same tx hash. Verifies the sweeper finalizes it via the
/// actual on-chain receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_submitted_with_real_receipt() {
    let url = redis_url();
    let mut redis = setup_redis(&url).await;
    flush_redis(&mut redis).await;

    let anvil = TestAnvil::spawn().unwrap();
    let deployer = anvil.signer(0).unwrap();
    let registry_addr = anvil.deploy_world_id_registry(deployer).await.unwrap();
    let rpc_url = anvil.endpoint();

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let sweeper_defaults = OrphanSweeperConfig::default();
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4200).into(),
        redis_url: url.clone(),
        request_timeout_secs: 10,
        rate_limit_window_secs: None,
        rate_limit_max_requests: None,
        sweeper_interval_secs: 9999, // don't auto-sweep during this test
        stale_queued_threshold_secs: sweeper_defaults.stale_queued_threshold_secs,
        stale_submitted_threshold_secs: sweeper_defaults.stale_submitted_threshold_secs,
    };

    let gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4200).await;
    let base = "http://127.0.0.1:4200";

    let body = world_id_core::api_types::CreateAccountRequest {
        recovery_address: Some(wallet_addr),
        authenticator_addresses: vec![address!("0x2222222222222222222222222222222222222222")],
        authenticator_pubkeys: vec![U256::from(100)],
        offchain_signer_commitment: U256::from(1),
    };

    let resp = client
        .post(format!("{base}/create-account"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _original_id = accepted.request_id.clone();

    let tx_hash = wait_for_finalized(&client, base, &_original_id).await;
    assert!(!tx_hash.is_empty());

    // Now inject a NEW request that references the same tx_hash, simulating
    // a replica that died before updating state.
    inject_request(
        &mut redis,
        "orphan-with-receipt",
        GatewayRequestKind::CreateAccount,
        GatewayRequestState::Submitted {
            tx_hash: tx_hash.clone(),
        },
        now_unix_secs() - 300,
    )
    .await;

    let tracker = RequestTracker::new(url, None).await;
    let provider = alloy::providers::ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
    let dyn_provider: alloy::providers::DynProvider = provider.erased();

    let config = OrphanSweeperConfig::default();
    sweep_once(&tracker, &dyn_provider, &config).await;

    let record = read_record(&mut redis, "orphan-with-receipt")
        .await
        .unwrap();
    assert!(
        matches!(record.status, GatewayRequestState::Finalized { .. }),
        "submitted request with on-chain receipt should be finalized by sweeper"
    );
    assert!(!is_in_pending_set(&mut redis, "orphan-with-receipt").await);

    let _ = gw.shutdown().await;
}
