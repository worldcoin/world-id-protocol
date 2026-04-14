//! **PROTO-4494 — Regression test: inflight lock must survive stall window**
//!
//! The Redis inflight lock (`gateway:inflight:create:<addr>`) prevents two
//! concurrent `createAccount` requests for the same authenticator address.
//! Its TTL must be long enough that it outlasts any realistic transaction
//! stall + sweeper cleanup window.  If the TTL is too short (e.g. 300s) and
//! a nonce stall keeps transactions in `Submitted` state for hours, the lock
//! expires and a duplicate request slips through.
//!
//! This test asserts the **correct** behaviour:
//!   - After simulating a stall that exceeds `STALE_SUBMITTED_THRESHOLD_SECS`
//!     (600s), the inflight lock must STILL be alive and reject duplicates.
//!
//! On unpatched code (`INFLIGHT_TTL = 300s`) the lock expires before the
//! stale-submitted threshold, so the duplicate is accepted — the test fails.
//!
//! Run (needs a Redis instance):
//!   REDIS_URL=redis://127.0.0.1:6379 \
//!     cargo test -p world-id-gateway --test test_inflight_ttl_expiry -- --nocapture

use redis::AsyncCommands;
use world_id_core::api_types::GatewayRequestKind;
use world_id_gateway::RequestTracker;

/// Returns the Redis URL from `REDIS_URL` env, falling back to localhost:6399.
fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6399".to_string())
}

/// The inflight Redis key the tracker creates for a create-account request.
fn inflight_key(addr: &str) -> String {
    format!("gateway:inflight:create:{addr}")
}

/// Create a tracker pointed at the given Redis URL.
async fn make_tracker(redis_url: &str) -> RequestTracker {
    RequestTracker::new(redis_url.to_string(), None, 300).await
}

/// The `STALE_SUBMITTED_THRESHOLD_SECS` default from gateway config.
/// The inflight TTL must exceed this value to prevent duplicates during stalls.
const STALE_SUBMITTED_THRESHOLD_SECS: u64 = 600;

/// Asserts that the inflight lock's TTL exceeds the stale-submitted threshold.
///
/// **Expected to FAIL on unpatched code** where `INFLIGHT_TTL = 300s`, which
/// is less than `STALE_SUBMITTED_THRESHOLD_SECS = 600s`.  A nonce stall can
/// keep a request in `Submitted` state for the full 600s, during which the
/// 300s lock expires and a duplicate slips through.
#[tokio::test(flavor = "multi_thread")]
async fn test_inflight_ttl_outlasts_stale_submitted_threshold() {
    let url = redis_url();
    let tracker = make_tracker(&url).await;
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();

    let addr = "0xee01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // ── Step 1: Submit a request ───────────────────────────────────
    let id = "ttl-check-001".to_string();
    tracker
        .new_request_with_id(
            id.clone(),
            GatewayRequestKind::CreateAccount,
            vec![addr.to_string()],
        )
        .await
        .expect("request should be accepted");

    // ── Step 2: Read the TTL that was set ──────────────────────────
    let key = inflight_key(addr);
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .unwrap();
    println!("inflight lock TTL: {ttl}s");
    println!("STALE_SUBMITTED_THRESHOLD_SECS: {STALE_SUBMITTED_THRESHOLD_SECS}s");

    // ── Step 3: Assert the TTL is long enough ──────────────────────
    assert!(
        ttl as u64 > STALE_SUBMITTED_THRESHOLD_SECS,
        "INFLIGHT_TTL ({ttl}s) must be greater than \
         STALE_SUBMITTED_THRESHOLD_SECS ({STALE_SUBMITTED_THRESHOLD_SECS}s). \
         Otherwise a nonce stall can cause the lock to expire before the \
         sweeper cleans up the request, allowing duplicates. \
         Increase INFLIGHT_TTL to at least 900s to fix."
    );
}

/// Asserts that after simulating the maximum stall duration, a duplicate
/// request for the same authenticator is still rejected.
///
/// We simulate the stall by fast-forwarding the lock's remaining TTL to just
/// above and just below `STALE_SUBMITTED_THRESHOLD_SECS` and checking
/// rejection.
///
/// **Expected to FAIL on unpatched code** because the 300s lock has already
/// expired by the time we check at `STALE_SUBMITTED_THRESHOLD_SECS`.
#[tokio::test(flavor = "multi_thread")]
async fn test_duplicate_rejected_after_stale_submitted_window() {
    let url = redis_url();
    let tracker = make_tracker(&url).await;
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();

    let addr = "0xee02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // ── Step 1: Submit a request ───────────────────────────────────
    let id1 = "stall-sim-001".to_string();
    tracker
        .new_request_with_id(
            id1.clone(),
            GatewayRequestKind::CreateAccount,
            vec![addr.to_string()],
        )
        .await
        .expect("first request should be accepted");

    // ── Step 2: Simulate time passing to the stale threshold ───────
    // We reduce the key's TTL to simulate that `STALE_SUBMITTED_THRESHOLD_SECS`
    // have elapsed since the lock was created.  If the original TTL was T,
    // after 600s the remaining TTL would be T − 600.
    //
    // Read current TTL and compute what would remain after 600s.
    let key = inflight_key(addr);
    let original_ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .unwrap();
    println!("original TTL: {original_ttl}s");

    let remaining = original_ttl - STALE_SUBMITTED_THRESHOLD_SECS as i64;
    println!("remaining TTL after {STALE_SUBMITTED_THRESHOLD_SECS}s stall: {remaining}s");

    if remaining <= 0 {
        // The lock would have already expired — this IS the bug.
        // The key no longer exists, so a duplicate will be accepted.
        // We delete it to simulate the expiry.
        let _: () = conn.del(&key).await.unwrap();
        println!("lock expired during stall window (remaining={remaining}s) — this is the bug");
    } else {
        // The lock survives — set its TTL to the simulated remaining value.
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(remaining)
            .query_async(&mut conn)
            .await
            .unwrap();
    }

    // ── Step 3: Attempt a duplicate ────────────────────────────────
    let id2 = "stall-sim-002".to_string();
    let result = tracker
        .new_request_with_id(
            id2,
            GatewayRequestKind::CreateAccount,
            vec![addr.to_string()],
        )
        .await;

    assert!(
        result.is_err(),
        "duplicate request must be REJECTED even after waiting \
         {STALE_SUBMITTED_THRESHOLD_SECS}s. The inflight lock expired too \
         early (INFLIGHT_TTL < STALE_SUBMITTED_THRESHOLD_SECS). \
         Increase INFLIGHT_TTL to fix."
    );
    println!("✅ duplicate correctly rejected after {STALE_SUBMITTED_THRESHOLD_SECS}s stall");
}
