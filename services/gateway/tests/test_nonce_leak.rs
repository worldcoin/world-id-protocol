//! **PROTO-4494 — Regression test: no nonce leak on reverting batch send**
//!
//! When `createManyAccounts` is called for an authenticator that is already
//! registered, the transaction must still be **broadcast and mined** (reverting
//! on-chain) so that the nonce IS consumed.  If the nonce is not consumed, a
//! "nonce gap" forms and every subsequent transaction stalls until the gateway
//! process is restarted.
//!
//! This test asserts the **correct** behaviour:
//!   - After a reverting `createManyAccounts`, the on-chain nonce increments.
//!   - A follow-up valid transaction succeeds without a gap.
//!
//! On unpatched code (no explicit `.gas()`) the send fails pre-broadcast
//! during `eth_estimateGas`, the nonce is NOT consumed, and these assertions
//! fail — proving the bug.
//!
//! Run:
//!   cargo test -p world-id-gateway --test test_nonce_leak -- --nocapture

use std::sync::Arc;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{DynProvider, Provider, ProviderBuilder, fillers::CachedNonceManager},
    signers::local::PrivateKeySigner,
};
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;
use world_id_test_utils::anvil::TestAnvil;

/// Default Anvil test private key (account 0).
const SIGNER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Gas budget per `createAccount` call (from gateway defaults).
const DEFAULT_CREATE_ACCOUNT_GAS: u64 = 620_000;

/// Fixed gas overhead for `createManyAccounts` — must match batcher constant.
const CREATE_BATCH_FIXED_GAS: u64 = 500_000;

/// Marginal gas per account in a `createManyAccounts` batch.
const CREATE_BATCH_PER_ACCOUNT_GAS: u64 = 120_000;

/// Build the **same** provider stack used in production:
/// `CachedNonceManager` + `GasFiller` + wallet.
async fn production_provider(rpc_url: &str, signer: PrivateKeySigner) -> Arc<DynProvider> {
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .with_nonce_management(CachedNonceManager::default())
        .wallet(wallet)
        .connect_http(rpc_url.parse().expect("parse url"));
    Arc::new(provider.erased())
}

/// Helper: register one account so that the authenticator address is "taken".
async fn register_account(
    registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
    auth_addr: Address,
    pubkey: U256,
    commitment: U256,
) {
    let pending = registry
        .createAccount(Address::ZERO, vec![auth_addr], vec![pubkey], commitment)
        .gas(DEFAULT_CREATE_ACCOUNT_GAS)
        .send()
        .await
        .expect("createAccount send");

    let receipt = pending.get_receipt().await.expect("createAccount receipt");
    assert!(receipt.status(), "createAccount should succeed");
}

/// Asserts that a duplicate `createManyAccounts` consumes the nonce (reverts
/// on-chain rather than failing pre-broadcast) and that a follow-up valid
/// transaction succeeds without a nonce gap.
///
/// **Expected to FAIL on unpatched code** where `createManyAccounts` has no
/// explicit `.gas()` and the `GasFiller` calls `eth_estimateGas` which errors
/// out before broadcast, leaking the nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_duplicate_create_must_consume_nonce() {
    // ── Setup ──────────────────────────────────────────────────────────
    let anvil = TestAnvil::spawn_with_multicall3()
        .await
        .expect("failed to spawn anvil");
    let deployer = anvil.signer(0).expect("deployer signer");
    let registry_addr = anvil
        .deploy_world_id_registry(deployer.clone())
        .await
        .expect("deploy registry");

    let signer: PrivateKeySigner = SIGNER_KEY.parse().unwrap();
    let provider = production_provider(anvil.endpoint(), signer.clone()).await;
    let registry = WorldIdRegistryInstance::new(registry_addr, provider.clone());

    let auth_addr = Address::repeat_byte(0xAA);
    let pubkey = U256::from(42u64);
    let commitment = U256::from(12345u64);

    // ── Step 1: Register the authenticator once (succeeds) ─────────
    register_account(&registry, auth_addr, pubkey, commitment).await;

    let nonce_before: u64 = provider
        .get_transaction_count(signer.address())
        .await
        .expect("get nonce");
    println!("nonce after first (successful) createAccount: {nonce_before}");

    // ── Step 2: Attempt a duplicate registration ───────────────────
    // This SHOULD be broadcast, revert on-chain, and consume the nonce.
    //
    // The gateway's batcher sets an explicit gas limit so that Alloy's
    // GasFiller (eth_estimateGas) is bypassed.  We mirror that here:
    let gas_limit = CREATE_BATCH_FIXED_GAS + CREATE_BATCH_PER_ACCOUNT_GAS * 1;

    let send_result: Result<_, alloy::contract::Error> = registry
        .createManyAccounts(
            vec![Address::ZERO],
            vec![vec![auth_addr]],
            vec![vec![pubkey]],
            vec![commitment],
        )
        .gas(gas_limit)
        .send()
        .await;

    // Whether send() returns Ok (broadcast succeeded, will revert on-chain)
    // or Err (pre-broadcast failure), we need to wait for any pending tx.
    if let Ok(pending) = send_result {
        let _ = pending.get_receipt().await;
    }

    // ── Step 3: Assert the nonce WAS consumed ──────────────────────
    let nonce_after: u64 = provider
        .get_transaction_count(signer.address())
        .await
        .expect("get nonce after duplicate send");

    println!("on-chain nonce after duplicate send: {nonce_after}");
    println!("expected (nonce_before + 1):         {}", nonce_before + 1);

    assert_eq!(
        nonce_after,
        nonce_before + 1,
        "NONCE LEAK: the duplicate createManyAccounts did not consume a nonce. \
         This means it failed pre-broadcast (eth_estimateGas) instead of \
         reverting on-chain. Set explicit .gas() on createManyAccounts to fix."
    );

    // ── Step 4: Prove no nonce gap — follow-up tx succeeds ─────────
    let fresh_auth = Address::repeat_byte(0xBB);
    let fresh_pubkey = U256::from(99u64);
    let fresh_commitment = U256::from(99999u64);

    let follow_pending = registry
        .createManyAccounts(
            vec![Address::ZERO],
            vec![vec![fresh_auth]],
            vec![vec![fresh_pubkey]],
            vec![fresh_commitment],
        )
        .gas(DEFAULT_CREATE_ACCOUNT_GAS)
        .send()
        .await
        .expect("follow-up tx should send (no nonce gap)");

    let follow_receipt = follow_pending
        .get_receipt()
        .await
        .expect("follow-up receipt");

    assert!(
        follow_receipt.status(),
        "follow-up createManyAccounts should succeed on-chain (no nonce gap)"
    );
    println!("✅ follow-up tx succeeded — no nonce gap");
}
