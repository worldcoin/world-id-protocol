use std::time::Duration;

use alloy::{
    primitives::{Address, U256, address},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use reqwest::{Client, StatusCode};
use world_id_core::{
    api_types::{
        GatewayStatusResponse, InsertAuthenticatorRequest, RecoverAccountRequest,
        RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    world_id_registry::{
        WorldIdRegistry, domain as ag_domain, sign_insert_authenticator, sign_recover_account,
        sign_remove_authenticator, sign_update_authenticator,
    },
};
use world_id_gateway::{GatewayConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_services_common::ProviderArgs;
use world_id_test_utils::anvil::TestAnvil;

use crate::common::{wait_for_finalized, wait_http_ready};

mod common;

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const GW_PORT: u16 = 4101;
const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

struct TestGateway {
    client: Client,
    base_url: String,
    registry_addr: Address,
    rpc_url: String,
    _handle: world_id_gateway::GatewayHandle,
    _anvil: TestAnvil,
}

async fn spawn_test_gateway(port: u16) -> TestGateway {
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

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, port).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_gateway_full_flow() {
    let gw = spawn_test_gateway(GW_PORT).await;

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    // Build Alloy provider for on-chain assertions and chain id
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());

    // First, create the initial account through the API so tree depth stays 0 for following ops
    let body_create = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["0x64"],
        "offchain_signer_commitment": "0x1",
    });
    let resp = gw
        .client
        .post(format!("{}/create-account", gw.base_url))
        .json(&body_create)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("create-account failed: status={status_code}, body={body}",);
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let create_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &create_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "create-account should return a finalized tx hash"
    );

    // Wait until createManyAccounts is reflected on-chain
    let deadline_ca = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed_after = contract
            .getPackedAccountData(wallet_addr)
            .call()
            .await
            .unwrap();
        if packed_after != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline_ca {
            panic!("timeout waiting for createManyAccounts mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Sanity: build provider and contract for on-chain assertions
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());
    // The wallet address must be registered as authenticator for account 1
    let packed = contract
        .getPackedAccountData(wallet_addr)
        .call()
        .await
        .unwrap();
    assert!(
        packed != U256::ZERO,
        "creator wallet not registered as authenticator"
    );

    let chain_id = provider.get_chain_id().await.unwrap();

    // EIP-712 domain via common helpers
    let domain = ag_domain(chain_id, gw.registry_addr);

    // Nonce tracker
    let mut nonce = U256::from(0);

    // insert-authenticator
    let new_auth2: Address = address!("0x00000000000000000000000000000000000000a2");
    let sig_ins = sign_insert_authenticator(
        &signer,
        1,
        new_auth2,
        1,
        U256::from(200),
        U256::from(2),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_ins = InsertAuthenticatorRequest {
        leaf_index: 1,
        new_authenticator_address: new_auth2,
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(2),
        signature: sig_ins.as_bytes().to_vec(),
        nonce,
        pubkey_id: 1,
        new_authenticator_pubkey: U256::from(200),
    };
    // Issue request to gateway
    let resp = gw
        .client
        .post(format!("{}/insert-authenticator", gw.base_url))
        .json(&body_ins)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!(
            "insert-authenticator failed: status={}, body={}",
            status_code, body
        );
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let insert_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &insert_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "insert-authenticator should return a finalized tx hash"
    );
    // wait until mapping shows up
    let deadline2 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .getPackedAccountData(new_auth2)
            .call()
            .await
            .unwrap();
        if v != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for insert-authenticator mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // increment nonce
    nonce += U256::from(1);

    // remove-authenticator (remove the one we inserted)
    let sig_rem = sign_remove_authenticator(
        &signer,
        1,
        new_auth2,
        1,
        U256::from(200),
        U256::from(3),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_rem = RemoveAuthenticatorRequest {
        leaf_index: 1,
        authenticator_address: new_auth2,
        old_offchain_signer_commitment: U256::from(2),
        new_offchain_signer_commitment: U256::from(3),
        signature: sig_rem.as_bytes().to_vec(),
        nonce,
        pubkey_id: Some(1),
        authenticator_pubkey: Some(U256::from(200)),
    };
    let resp = gw
        .client
        .post(format!("{}/remove-authenticator", gw.base_url))
        .json(&body_rem)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("remove-authenticator failed: status={status_code}, body={body}",);
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let remove_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &remove_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "remove-authenticator should return a finalized tx hash"
    );
    // wait until mapping cleared
    let deadline3 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .getPackedAccountData(new_auth2)
            .call()
            .await
            .unwrap();
        if v == U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline3 {
            panic!("timeout waiting for remove-authenticator mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    nonce += U256::from(1);

    let signer_new = PrivateKeySigner::random();
    let wallet_addr_new: Address = signer_new.address();

    // recover-account (signed by recovery address == wallet)
    let sig_rec = sign_recover_account(
        &signer,
        1,
        wallet_addr_new,
        U256::from(300),
        U256::from(4),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_rec = RecoverAccountRequest {
        leaf_index: 1,
        new_authenticator_address: wallet_addr_new,
        old_offchain_signer_commitment: U256::from(3),
        new_offchain_signer_commitment: U256::from(4),
        signature: sig_rec.as_bytes().to_vec(),
        nonce,
        new_authenticator_pubkey: Some(U256::from(300)),
    };
    let resp = gw
        .client
        .post(format!("{}/recover-account", gw.base_url))
        .json(&body_rec)
        .send()
        .await
        .unwrap();

    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!(
            "recover-account failed: status={}, body={}",
            status_code, body
        );
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let recover_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &recover_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "recover-account should return a finalized tx hash"
    );
    // wait mapping
    let deadline4 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .getPackedAccountData(wallet_addr_new)
            .call()
            .await
            .unwrap();
        if v != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline4 {
            panic!("timeout waiting for recover-account mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    nonce += U256::from(1);

    // update-authenticator: replace original wallet authenticator with new one
    let new_auth4: Address = address!("0x00000000000000000000000000000000000000a4");
    let sig_upd = sign_update_authenticator(
        &signer_new,
        1,
        wallet_addr_new,
        new_auth4,
        0,
        U256::from(400),
        U256::from(5),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_upd = UpdateAuthenticatorRequest {
        leaf_index: 1,
        old_authenticator_address: wallet_addr_new,
        new_authenticator_address: new_auth4,
        old_offchain_signer_commitment: U256::from(4),
        new_offchain_signer_commitment: U256::from(5),
        signature: sig_upd.as_bytes().to_vec(),
        nonce,
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
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!(
            "update-authenticator failed: status={}, body={}",
            status_code, body
        );
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let update_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &update_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "update-authenticator should return a finalized tx hash"
    );
    // wait mapping: old removed, new present
    let deadline5 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let old_v = contract
            .getPackedAccountData(wallet_addr_new)
            .call()
            .await
            .unwrap();
        let new_v = contract
            .getPackedAccountData(new_auth4)
            .call()
            .await
            .unwrap();
        if old_v == U256::ZERO && new_v != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline5 {
            panic!("timeout waiting for update-authenticator mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_authenticator_already_exists_error_code() {
    let gw = spawn_test_gateway(4102).await;

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());

    let body_create = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["100"],
        "offchain_signer_commitment": "1",
    });
    let resp = gw
        .client
        .post(format!("{}/create-account", gw.base_url))
        .json(&body_create)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let create_request_id = accepted.request_id.clone();
    let _tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &create_request_id).await;

    // Wait until createManyAccounts is reflected on-chain
    let deadline_ca = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed_after = contract
            .getPackedAccountData(wallet_addr)
            .call()
            .await
            .unwrap();
        if packed_after != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline_ca {
            panic!("timeout waiting for createManyAccounts mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    // Try to insert the same authenticator again (wallet_addr is already an authenticator)
    let nonce = U256::from(0);
    let sig_ins = sign_insert_authenticator(
        &signer,
        1,
        wallet_addr, // Same address that's already an authenticator for account 1
        0,
        U256::from(100),
        U256::from(2),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_ins = InsertAuthenticatorRequest {
        leaf_index: 1,
        new_authenticator_address: wallet_addr,
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(2),
        signature: sig_ins.as_bytes().to_vec(),
        nonce,
        pubkey_id: 0,
        new_authenticator_pubkey: U256::from(100),
    };

    let resp = gw
        .client
        .post(format!("{}/insert-authenticator", gw.base_url))
        .json(&body_ins)
        .send()
        .await
        .unwrap();

    // Simulation should fail synchronously and return 400 immediately
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let error_body: serde_json::Value = resp.json().await.unwrap();
    // Check string response, or message/code field for the error
    let error_msg = error_body
        .as_str()
        .or_else(|| error_body.get("message").and_then(|e| e.as_str()))
        .or_else(|| error_body.get("code").and_then(|e| e.as_str()))
        .unwrap_or("");
    assert!(
        error_msg
            .to_lowercase()
            .replace('_', " ")
            .contains("authenticator already exists"),
        "Error should indicate 'authenticator already exists', got: {error_msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_same_authenticator_different_accounts() {
    let gw = spawn_test_gateway(4103).await;

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    // Create first account with wallet_addr as authenticator
    let body_create1 = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["100"],
        "offchain_signer_commitment": "1",
    });
    let resp = gw
        .client
        .post(format!("{}/create-account", gw.base_url))
        .json(&body_create1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let request_id_1 = accepted.request_id.clone();
    let _tx_hash_1 = wait_for_finalized(&gw.client, &gw.base_url, &request_id_1).await;

    // Try to create second account with the SAME wallet_addr as authenticator
    let body_create2 = serde_json::json!({
        "recovery_address": address!("0x0000000000000000000000000000000000000002").to_string(),
        "authenticator_addresses": [wallet_addr.to_string()], // Same authenticator!
        "authenticator_pubkeys": ["200"],
        "offchain_signer_commitment": "2",
    });
    let resp = gw
        .client
        .post(format!("{}/create-account", gw.base_url))
        .json(&body_create2)
        .send()
        .await
        .unwrap();

    // Simulation should fail synchronously and return 400 immediately
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let error_body: serde_json::Value = resp.json().await.unwrap();
    // Check string response, or message/code field for the error
    let error_msg = error_body
        .as_str()
        .or_else(|| error_body.get("message").and_then(|e| e.as_str()))
        .or_else(|| error_body.get("code").and_then(|e| e.as_str()))
        .unwrap_or("");
    assert!(
        error_msg
            .to_lowercase()
            .replace('_', " ")
            .contains("authenticator already exists"),
        "Error should indicate 'authenticator already exists', got: {error_msg}"
    );
}
