use std::time::Duration;

use alloy::primitives::U256;

use crate::setup::{INITIAL_ISSUER_PUBKEY, INITIAL_OPRF_PUBKEY, INITIAL_ROOT, WorldIDTestHarness};

/// Full permissioned relay E2E: deploy, relay initial state, update registries,
/// relay updated state, verify final satellite state.
///
/// Requires Docker (testcontainers) and forge (contract deployment).
/// Run: `cargo test -p world-id-relay --test testsuite -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires docker + forge"]
async fn test_permissioned_relay_e2e() {
    // ── Setup: spawn chains + deploy contracts ──
    eprintln!("=== Setting up test harness ===");
    let harness = WorldIDTestHarness::setup()
        .await
        .expect("harness setup failed");

    eprintln!(
        "  World Chain: {} (source={})",
        harness.worldchain.endpoint(),
        harness.source_addrs.source_proxy
    );
    eprintln!(
        "  Destination: {} (satellite={}, gateway={})",
        harness.destination.endpoint(),
        harness.dest_addrs.satellite_proxy,
        harness.dest_addrs.gateway
    );

    // ── Start relay (in-process) ──
    eprintln!("=== Starting relay ===");
    let _relay = harness
        .spawn_relay(Duration::from_secs(5), Duration::from_secs(2))
        .expect("spawn relay failed");

    // ── Round 1: wait for initial state (root=1000) ──
    eprintln!("=== Waiting for round 1 (root={INITIAL_ROOT}) ===");
    harness
        .poll_dest_root(U256::from(INITIAL_ROOT), Duration::from_secs(60))
        .await
        .expect("round 1 timed out");
    eprintln!("  root={INITIAL_ROOT} arrived");

    // Verify initial issuer and OPRF pubkeys
    let (ix, iy) = harness
        .query_dest_issuer_pubkey()
        .await
        .expect("query issuer pubkey");
    assert_eq!(
        (ix, iy),
        (
            U256::from(INITIAL_ISSUER_PUBKEY.0),
            U256::from(INITIAL_ISSUER_PUBKEY.1)
        ),
        "initial issuer pubkey mismatch"
    );
    eprintln!(
        "  issuer#1=({}, {}) confirmed",
        INITIAL_ISSUER_PUBKEY.0, INITIAL_ISSUER_PUBKEY.1
    );

    let (ox, oy) = harness
        .query_dest_oprf_pubkey()
        .await
        .expect("query oprf pubkey");
    assert_eq!(
        (ox, oy),
        (
            U256::from(INITIAL_OPRF_PUBKEY.0),
            U256::from(INITIAL_OPRF_PUBKEY.1)
        ),
        "initial oprf pubkey mismatch"
    );
    eprintln!(
        "  oprf#1=({}, {}) confirmed",
        INITIAL_OPRF_PUBKEY.0, INITIAL_OPRF_PUBKEY.1
    );

    // ── Round 2: update registries, wait for new state ──
    let new_root = 2000u64;
    let new_issuer = (55u64, 66u64);
    eprintln!(
        "=== Updating registries: root={new_root}, issuer#1=({}, {}) ===",
        new_issuer.0, new_issuer.1
    );

    harness
        .update_registry(
            U256::from(new_root),
            U256::from(new_issuer.0),
            U256::from(new_issuer.1),
        )
        .await
        .expect("update registry failed");

    eprintln!("=== Waiting for round 2 (root={new_root}) ===");
    harness
        .poll_dest_root(U256::from(new_root), Duration::from_secs(60))
        .await
        .expect("round 2 timed out");
    eprintln!("  root={new_root} arrived");

    // ── Verify final state ──
    eprintln!("=== Verifying final state ===");

    let (ix, iy) = harness
        .query_dest_issuer_pubkey()
        .await
        .expect("query final issuer pubkey");
    assert_eq!(
        (ix, iy),
        (U256::from(new_issuer.0), U256::from(new_issuer.1)),
        "updated issuer pubkey mismatch"
    );
    eprintln!("  issuer#1=({}, {}) confirmed", new_issuer.0, new_issuer.1);

    // OPRF key was not updated — should remain at initial values
    let (ox, oy) = harness
        .query_dest_oprf_pubkey()
        .await
        .expect("query final oprf pubkey");
    assert_eq!(
        (ox, oy),
        (
            U256::from(INITIAL_OPRF_PUBKEY.0),
            U256::from(INITIAL_OPRF_PUBKEY.1)
        ),
        "oprf pubkey should be unchanged"
    );
    eprintln!(
        "  oprf#1=({}, {}) unchanged",
        INITIAL_OPRF_PUBKEY.0, INITIAL_OPRF_PUBKEY.1
    );

    // Keccak chain head should be non-zero (state was bridged)
    let chain_head = harness
        .query_dest_chain_head()
        .await
        .expect("query chain head");
    assert_ne!(chain_head, [0u8; 32], "chain head should be non-zero");
    eprintln!("  chain head non-zero confirmed");

    eprintln!("=== ALL ASSERTIONS PASSED ===");
}
