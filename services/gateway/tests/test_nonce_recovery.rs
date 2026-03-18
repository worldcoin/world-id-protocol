//! Integration tests that verify the gateway recovers from nonce-related
//! failures when transaction sends fail (e.g. "insufficient funds").
//!
//! These tests reproduce the exact production scenario: gateway signer has zero
//! balance, `createAccountMany` fails with "insufficient funds", the nonce gets
//! released, and subsequent requests succeed once the signer is funded.

mod common;

use std::time::Duration;

use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use reqwest::{Client, StatusCode};
use world_id_core::api_types::{GatewayRequestState, GatewayStatusResponse};
use world_id_gateway::{BatchPolicyConfig, GatewayConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_services_common::ProviderArgs;
use world_id_test_utils::anvil::TestAnvil;

use crate::common::{wait_for_finalized, wait_http_ready};

/// Anvil account 0 private key — also used as the gateway signer and deployer.
const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Anvil account 0 address (derived from `GW_PRIVATE_KEY`).
const GW_SIGNER_ADDR: Address =
    alloy::primitives::address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

/// Atomic counter used to assign each test gateway a unique Redis DB index
/// so that concurrent tests don't share in-flight keys.
///
/// Redis supports databases 0–15 by default (`databases 16` in redis.conf).
/// `test_inflight.rs` starts at 1 and uses DBs 1–8.
/// This file starts at 10, leaving DBs 10–15 for the tests here.
static REDIS_DB_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(10);

// ---------------------------------------------------------------------------
// Helper: wait for a request to reach the Failed state
// ---------------------------------------------------------------------------

/// Polls the gateway status endpoint until the request reaches `Failed` state.
/// Returns the error string from the failure. Panics if the request finalizes
/// successfully (unexpected) or if the 30-second timeout is exceeded.
async fn wait_for_failed(client: &Client, base: &str, request_id: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let resp = client
            .get(format!("{base}/status/{request_id}"))
            .send()
            .await
            .unwrap();
        let status_code = resp.status();
        if status_code == StatusCode::NOT_FOUND {
            panic!("request {request_id} not found");
        }
        if !status_code.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            panic!(
                "status check for {request_id} failed: {} body={}",
                status_code, body_text
            );
        }
        let body: GatewayStatusResponse = resp.json().await.unwrap();
        match body.status {
            GatewayRequestState::Failed { error, .. } => return error,
            GatewayRequestState::Finalized { .. } => {
                panic!("request {request_id} unexpectedly finalized (expected failure)");
            }
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!("timeout waiting for request {request_id} to fail");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: set Anvil account balance via raw RPC
// ---------------------------------------------------------------------------

/// Calls `anvil_setBalance` to set the balance of `address` to `amount`.
async fn set_anvil_balance<P: Provider>(provider: &P, address: Address, amount: U256) {
    provider
        .raw_request::<_, ()>("anvil_setBalance".into(), (address, amount))
        .await
        .expect("anvil_setBalance failed");
}

// ---------------------------------------------------------------------------
// Helper: build a create-account JSON body with unique random addresses
// ---------------------------------------------------------------------------

fn create_account_body() -> (serde_json::Value, Address) {
    let signer = PrivateKeySigner::random();
    let addr = signer.address();
    let body = serde_json::json!({
        "recovery_address": addr.to_string(),
        "authenticator_addresses": [addr.to_string()],
        "authenticator_pubkeys": ["0x64"],
        "offchain_signer_commitment": "0x1",
    });
    (body, addr)
}

/// Submits a create-account request and returns the request ID.
async fn submit_create_account(client: &Client, base_url: &str) -> String {
    let (body, _) = create_account_body();
    let resp = client
        .post(format!("{base_url}/create-account"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body_text = resp.text().await.unwrap_or_default();
        panic!("create-account request rejected: status={status_code}, body={body_text}");
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    accepted.request_id
}

// ---------------------------------------------------------------------------
// Test gateway setup
// ---------------------------------------------------------------------------

struct TestGateway {
    client: Client,
    base_url: String,
    rpc_url: String,
    _handle: world_id_gateway::GatewayHandle,
    _anvil: TestAnvil,
}

/// Spawns a forked Anvil, deploys the WorldIDRegistry, and starts a gateway.
///
/// If `drain_signer` is true the gateway signer's balance is set to zero
/// *before* the gateway is started, so the first batch send will fail.
async fn spawn_test_gateway(drain_signer: bool) -> TestGateway {
    let mut fork_url = std::env::var("TESTS_RPC_FORK_URL").unwrap_or_default();
    if fork_url.is_empty() {
        fork_url = RPC_FORK_URL.to_string();
    }
    let anvil = TestAnvil::spawn_fork(&fork_url).expect("failed to spawn forked anvil");

    // Deploy registry using account 0 (the same key as the gateway signer).
    let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
    let _registry_addr = anvil
        .deploy_world_id_registry(deployer)
        .await
        .expect("failed to deploy WorldIDRegistry");

    let rpc_url = anvil.endpoint().to_string();

    // Build an Alloy provider for balance manipulation.
    let provider = alloy::providers::ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

    if drain_signer {
        set_anvil_balance(&provider, GW_SIGNER_ADDR, U256::ZERO).await;
    }

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());

    let batch_ms: u64 = 200;
    let max_wait_secs = (batch_ms / 1000).max(1);
    let reeval_ms = batch_ms.min(200);

    let redis_url = {
        let base =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
        let db = REDIS_DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{base}/{db}")
    };

    let cfg = GatewayConfig {
        registry_addr: _registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_policy: BatchPolicyConfig {
            max_wait_secs,
            reeval_ms,
            ..BatchPolicyConfig::default()
        },
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: redis_url.clone(),
        request_timeout_secs: 10,
        rate_limit_window_secs: None,
        rate_limit_max_requests: None,
        sweeper_interval_secs: max_wait_secs + 1,
        stale_queued_threshold_secs: max_wait_secs + 1,
        stale_submitted_threshold_secs: 600,
    };

    // Flush the Redis DB to avoid stale keys from prior runs.
    {
        let client = redis::Client::open(cfg.redis_url.as_str()).expect("redis open");
        let mut conn = client.get_connection().expect("redis connect");
        redis::cmd("FLUSHDB").exec(&mut conn).expect("FLUSHDB");
    }

    let handle = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let addr = handle.listen_addr;
    let base_url = format!("http://{}:{}", addr.ip(), addr.port());

    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, addr.port()).await;

    TestGateway {
        client,
        base_url,
        rpc_url,
        _handle: handle,
        _anvil: anvil,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// Reproduces the production nonce-poisoning scenario:
///
/// 1. Gateway signer has zero balance.
/// 2. A `create-account` request is submitted.
/// 3. The batch send fails with "insufficient funds".
/// 4. The nonce must be released so the nonce manager is not poisoned.
/// 5. After funding the signer, the next request succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonce_released_after_insufficient_funds() {
    // -- Setup: deploy registry, then drain the gateway signer --
    let gw = spawn_test_gateway(true).await;

    // -- Step 1: submit a request that will fail on-chain --
    let req_id = submit_create_account(&gw.client, &gw.base_url).await;

    // -- Step 2: wait for the request to fail --
    let error = wait_for_failed(&gw.client, &gw.base_url, &req_id).await;
    let error_lower = error.to_lowercase();
    assert!(
        error_lower.contains("insufficient funds") || error_lower.contains("insufficient balance"),
        "expected 'insufficient funds' error, got: {error}"
    );

    // -- Step 3: fund the signer with 10 ETH --
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(gw.rpc_url.parse().unwrap());
    let ten_eth = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    set_anvil_balance(&provider, GW_SIGNER_ADDR, ten_eth).await;

    // -- Step 4: submit another request — this one must succeed --
    let req_id_2 = submit_create_account(&gw.client, &gw.base_url).await;
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &req_id_2).await;
    assert!(
        !tx_hash.is_empty(),
        "second request should finalize with a tx hash, proving the nonce was released"
    );
}

/// Verifies that multiple *concurrent* send failures all release their nonces
/// correctly, so the nonce manager is never permanently poisoned.
///
/// # Why concurrency matters here
///
/// PR #569 introduces a CAS (compare-and-swap) based nonce-release mechanism in
/// the gateway.  Each batch allocator records the nonce value it consumed and,
/// on failure, attempts to CAS the Redis counter back to `allocated_nonce`
/// (i.e. `expected = allocated_nonce + 1`, `set = allocated_nonce`).
///
/// When two batches are allocated and fail at roughly the same time, the
/// following problematic ordering can occur:
///
/// 1. Batch A allocates nonce N   → Redis counter is now N+1.
/// 2. Batch B allocates nonce N+1 → Redis counter is now N+2.
/// 3. Batch A's send fails; its CAS fires:
///    `expect N+1, set N` → **succeeds** (counter moves N+1 → N).
/// 4. Batch B's send fails; its CAS fires:
///    `expect N+2, set N+1` → **fails** (counter is N, not N+2).
///    Nonce N+1 is never released; the counter stays at N and nonce N+1
///    becomes a permanent gap — future batches will skip it.
///
/// The sequential version of this test (one failure at a time, wait between
/// each) cannot reproduce this race because each CAS completes before the next
/// allocation begins.  By submitting all requests and awaiting all failures
/// concurrently we exercise the overlapping-CAS window.
///
/// # Test steps
///
/// 1. Gateway signer has zero balance.
/// 2. Three requests are submitted **concurrently**; all fail with
///    "insufficient funds".
/// 3. After funding the signer, the fourth request succeeds, proving that all
///    three nonces were correctly released (no gap remains).
// 4 worker threads so that the three concurrent HTTP futures can be polled
// in parallel, giving the gateway a real chance to batch them together and
// maximising the window in which all CAS releases overlap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_consecutive_failures_recover() {
    use futures::future::join_all;

    // -- Setup: deploy registry, then drain the gateway signer --
    let gw = spawn_test_gateway(true).await;

    // -- Submit 3 requests concurrently --
    //
    // Fire all HTTP submissions in parallel so the gateway can batch them
    // together. This maximises the chance that all three allocators hold their
    // nonces simultaneously when they attempt the CAS release on failure.
    let submit_futs = (0..3).map(|_| submit_create_account(&gw.client, &gw.base_url));
    let req_ids: Vec<String> = join_all(submit_futs).await;

    // -- Await all failures concurrently --
    //
    // Polling all three status endpoints in parallel keeps the failure windows
    // overlapping; if we polled sequentially the later CAS releases would
    // happen long after the earlier ones, defeating the purpose.
    let wait_futs = req_ids
        .iter()
        .map(|id| wait_for_failed(&gw.client, &gw.base_url, id));
    let errors: Vec<String> = join_all(wait_futs).await;

    for (i, error) in errors.iter().enumerate() {
        let error_lower = error.to_lowercase();
        assert!(
            error_lower.contains("insufficient funds")
                || error_lower.contains("insufficient balance"),
            "request #{i} expected 'insufficient funds' error, got: {error}"
        );
    }

    // -- Fund the signer with 10 ETH --
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(gw.rpc_url.parse().unwrap());
    let ten_eth = U256::from(10_000_000_000_000_000_000u128);
    set_anvil_balance(&provider, GW_SIGNER_ADDR, ten_eth).await;

    // -- Submit a fourth request — must succeed --
    //
    // If any of the three concurrent CAS releases left a gap the nonce counter
    // will be stuck and this request will time out or fail.
    let req_id_4 = submit_create_account(&gw.client, &gw.base_url).await;
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &req_id_4).await;
    assert!(
        !tx_hash.is_empty(),
        "fourth request should finalize after funding, proving all 3 nonces were released \
         (no CAS-induced gap)"
    );
}
