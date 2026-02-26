#![cfg(feature = "integration-tests")]

use std::time::Duration;

use alloy::{
    primitives::{Address, U256, address},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use redis::aio::ConnectionManager;
use reqwest::{Client, StatusCode};
use world_id_core::{
    api_types::{
        GatewayStatusResponse, InsertAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    world_id_registry::{
        domain as ag_domain, sign_insert_authenticator, sign_update_authenticator,
    },
};
use world_id_gateway::{GatewayConfig, OrphanSweeperConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_services_common::ProviderArgs;
use world_id_test_utils::anvil::TestAnvil;

use crate::common::{wait_for_finalized, wait_http_ready};

mod common;

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

struct TestGateway {
    client: Client,
    base_url: String,
    registry_addr: Address,
    rpc_url: String,
    _handle: world_id_gateway::GatewayHandle,
    _anvil: TestAnvil,
}

async fn set_up_redis(redis_url: &str) -> ConnectionManager {
    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    client.get_connection_manager().await.unwrap()
}

async fn flush_redis(redis: &mut ConnectionManager) {
    use redis::AsyncTypedCommands;
    redis.flushdb().await.unwrap();
}

async fn spawn_test_gateway(port: u16, batch_ms: u64) -> TestGateway {
    let mut fork_url = std::env::var("TESTS_RPC_FORK_URL").unwrap_or_default();
    if fork_url.is_empty() {
        fork_url = RPC_FORK_URL.to_string();
    }
    let anvil = TestAnvil::spawn_fork(&fork_url).expect("failed to spawn forked anvil");
    let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
    let registry_addr = anvil
        .deploy_world_id_registry(deployer)
        .await
        .expect("failed to deploy WorldIDRegistry");
    let rpc_url = anvil.endpoint().to_string();

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let mut redis = set_up_redis(&redis_url).await;
    flush_redis(&mut redis).await;

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, port).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url,
        request_timeout_secs: 30,
        rate_limit_window_secs: None,
        rate_limit_max_requests: None,
        sweeper: OrphanSweeperConfig::default(),
    };
    let handle = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");

    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, port).await;

    TestGateway {
        client,
        base_url: format!("http://127.0.0.1:{port}"),
        registry_addr,
        rpc_url,
        _handle: handle,
        _anvil: anvil,
    }
}

/// Creates an account and waits for on-chain finalization. Returns the signer
/// and the on-chain offchain_signer_commitment after creation.
async fn create_account_and_wait(
    gw: &TestGateway,
    signer: &PrivateKeySigner,
) -> String {
    let wallet_addr: Address = signer.address();

    let body = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["0x64"],
        "offchain_signer_commitment": "0x1",
    });
    let resp = gw
        .client
        .post(format!("{}/create-account", gw.base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("create-account failed: status={status_code}, body={body}");
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let request_id = accepted.request_id.clone();
    wait_for_finalized(&gw.client, &gw.base_url, &request_id).await;

    // Wait until on-chain mapping is visible
    let provider = alloy::providers::ProviderBuilder::new()
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract =
        world_id_core::world_id_registry::WorldIdRegistry::new(gw.registry_addr, provider);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed = contract
            .getPackedAccountData(wallet_addr)
            .call()
            .await
            .unwrap();
        if packed != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for createAccount mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    request_id
}

/// Sends an insert-authenticator request and returns the (status_code, response_body).
async fn send_insert_authenticator(
    gw: &TestGateway,
    signer: &PrivateKeySigner,
    leaf_index: u64,
    new_auth_address: Address,
    pubkey_id: u32,
    new_pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
    nonce: U256,
) -> (StatusCode, serde_json::Value) {
    let provider = alloy::providers::ProviderBuilder::new()
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let sig = sign_insert_authenticator(
        signer,
        leaf_index,
        new_auth_address,
        pubkey_id,
        new_pubkey,
        new_commitment,
        nonce,
        &domain,
    )
    .await
    .unwrap();

    let body = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: new_auth_address,
        old_offchain_signer_commitment: old_commitment,
        new_offchain_signer_commitment: new_commitment,
        signature: sig.as_bytes().to_vec(),
        nonce,
        pubkey_id,
        new_authenticator_pubkey: new_pubkey,
    };

    let resp = gw
        .client
        .post(format!("{}/insert-authenticator", gw.base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

/// Two insert-authenticator requests for the same leaf_index: second should be
/// rejected with `duplicate_request_in_flight`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_duplicate_insert_rejected() {
    // Long batch window so first request stays in-flight
    let gw = spawn_test_gateway(4107, 5000).await;

    let signer = PrivateKeySigner::random();
    create_account_and_wait(&gw, &signer).await;

    // First insert — should succeed
    let (status1, _) = send_insert_authenticator(
        &gw,
        &signer,
        1,
        address!("0x00000000000000000000000000000000000000a2"),
        1,
        U256::from(200),
        U256::from(1),
        U256::from(2),
        U256::from(0),
    )
    .await;
    assert_eq!(status1, StatusCode::OK, "first insert should succeed");

    // Second insert for the SAME leaf_index — should be rejected
    let (status2, body2) = send_insert_authenticator(
        &gw,
        &signer,
        1,
        address!("0x00000000000000000000000000000000000000a3"),
        2,
        U256::from(300),
        U256::from(1),
        U256::from(3),
        U256::from(0),
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "second insert for same leaf_index should be rejected"
    );
    assert_eq!(body2["code"], "duplicate_request_in_flight");
}

/// Two insert-authenticator requests for different leaf_indices should both be
/// accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_different_leaf_index_allowed() {
    let gw = spawn_test_gateway(4108, 5000).await;

    let signer1 = PrivateKeySigner::random();
    let signer2 = PrivateKeySigner::random();

    create_account_and_wait(&gw, &signer1).await;
    create_account_and_wait(&gw, &signer2).await;

    // Insert for account 1 (leaf_index=1)
    let (status1, _) = send_insert_authenticator(
        &gw,
        &signer1,
        1,
        address!("0x00000000000000000000000000000000000000b1"),
        1,
        U256::from(200),
        U256::from(1),
        U256::from(2),
        U256::from(0),
    )
    .await;
    assert_eq!(status1, StatusCode::OK, "insert for leaf_index=1 should succeed");

    // Insert for account 2 (leaf_index=2) — should also succeed
    let (status2, _) = send_insert_authenticator(
        &gw,
        &signer2,
        2,
        address!("0x00000000000000000000000000000000000000b2"),
        1,
        U256::from(300),
        U256::from(1),
        U256::from(3),
        U256::from(0),
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "insert for different leaf_index should also succeed"
    );
}

/// After the first operation finalizes, a subsequent operation for the same
/// leaf_index should be accepted (lock released).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lock_released_after_finalization() {
    // Short batch window so the first request finalizes quickly
    let gw = spawn_test_gateway(4109, 200).await;

    let signer = PrivateKeySigner::random();
    create_account_and_wait(&gw, &signer).await;

    // First insert — send and wait for finalization
    let (status1, body1) = send_insert_authenticator(
        &gw,
        &signer,
        1,
        address!("0x00000000000000000000000000000000000000c1"),
        1,
        U256::from(200),
        U256::from(1),
        U256::from(2),
        U256::from(0),
    )
    .await;
    assert_eq!(status1, StatusCode::OK, "first insert should succeed");
    let request_id = body1["request_id"].as_str().unwrap();
    wait_for_finalized(&gw.client, &gw.base_url, request_id).await;

    // Second operation (update) for the same leaf_index — should be accepted
    let provider = alloy::providers::ProviderBuilder::new()
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let sig_upd = sign_update_authenticator(
        &signer,
        1,
        signer.address(),
        address!("0x00000000000000000000000000000000000000c2"),
        0,
        U256::from(400),
        U256::from(3),
        U256::from(1), // nonce=1 after first op
        &domain,
    )
    .await
    .unwrap();

    let body_upd = UpdateAuthenticatorRequest {
        leaf_index: 1,
        old_authenticator_address: signer.address(),
        new_authenticator_address: address!("0x00000000000000000000000000000000000000c2"),
        old_offchain_signer_commitment: U256::from(2),
        new_offchain_signer_commitment: U256::from(3),
        signature: sig_upd.as_bytes().to_vec(),
        nonce: U256::from(1),
        pubkey_id: 0,
        new_authenticator_pubkey: U256::from(400),
    };

    let resp = gw
        .client
        .post(format!("{}/update-authenticator", gw.base_url))
        .json(&body_upd)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "operation after finalization should succeed"
    );
}

/// An insert-authenticator followed immediately by an update-authenticator for
/// the same leaf_index: the update should be rejected (cross-operation-type conflict).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cross_operation_type_conflict() {
    let gw = spawn_test_gateway(4110, 5000).await;

    let signer = PrivateKeySigner::random();
    create_account_and_wait(&gw, &signer).await;

    // Insert — should succeed
    let (status1, _) = send_insert_authenticator(
        &gw,
        &signer,
        1,
        address!("0x00000000000000000000000000000000000000d1"),
        1,
        U256::from(200),
        U256::from(1),
        U256::from(2),
        U256::from(0),
    )
    .await;
    assert_eq!(status1, StatusCode::OK, "insert should succeed");

    // Update for the SAME leaf_index while insert is in-flight — should be rejected
    let provider = alloy::providers::ProviderBuilder::new()
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let sig_upd = sign_update_authenticator(
        &signer,
        1,
        signer.address(),
        address!("0x00000000000000000000000000000000000000d2"),
        0,
        U256::from(400),
        U256::from(3),
        U256::from(1),
        &domain,
    )
    .await
    .unwrap();

    let body_upd = UpdateAuthenticatorRequest {
        leaf_index: 1,
        old_authenticator_address: signer.address(),
        new_authenticator_address: address!("0x00000000000000000000000000000000000000d2"),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(3),
        signature: sig_upd.as_bytes().to_vec(),
        nonce: U256::from(1),
        pubkey_id: 0,
        new_authenticator_pubkey: U256::from(400),
    };

    let resp = gw
        .client
        .post(format!("{}/update-authenticator", gw.base_url))
        .json(&body_upd)
        .send()
        .await
        .unwrap();
    let status2 = resp.status();
    let body2: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "update while insert is in-flight should be rejected"
    );
    assert_eq!(body2["code"], "duplicate_request_in_flight");
}
