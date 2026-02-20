#![cfg(feature = "integration-tests")]

use alloy::{
    primitives::{Address, Bytes, U256, address},
    signers::{Signer, local::PrivateKeySigner},
    sol_types::SolStruct,
};
use redis::aio::ConnectionManager;
use reqwest::{Client, StatusCode};
use world_id_core::{
    api_types::{InsertAuthenticatorRequest, UpdateAuthenticatorRequest},
    world_id_registry::{InsertAuthenticatorTypedData, UpdateAuthenticatorTypedData},
};
use world_id_gateway::{GatewayConfig, spawn_gateway_for_tests};
use world_id_services_common::{ProviderArgs, SignerArgs};
use world_id_test_utils::anvil::TestAnvil;

use crate::common::wait_http_ready;

mod common;

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async fn set_up_redis(redis_url: &str) -> ConnectionManager {
    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    client.get_connection_manager().await.unwrap()
}

async fn flush_redis(redis: &mut ConnectionManager) {
    use redis::AsyncTypedCommands;
    redis.flushdb().await.unwrap();
}

/// Helper to sign an InsertAuthenticator request
#[allow(clippy::too_many_arguments)]
async fn sign_insert_authenticator(
    leaf_index: u64,
    new_authenticator_address: Address,
    pubkey_id: u8,
    new_authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    signer: &PrivateKeySigner,
    chain_id: u64,
    verifying_contract: Address,
) -> Bytes {
    let typed_data = InsertAuthenticatorTypedData {
        leafIndex: leaf_index,
        newAuthenticatorAddress: new_authenticator_address,
        pubkeyId: pubkey_id as u32,
        newAuthenticatorPubkey: new_authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };

    let domain = alloy::sol_types::eip712_domain! {
        name: "WorldIDRegistry",
        version: "1.0",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    };

    let hash = typed_data.eip712_signing_hash(&domain);
    let signature = signer.sign_hash(&hash).await.unwrap();

    Bytes::from(signature.as_bytes())
}

#[tokio::test]
async fn test_rate_limit_basic() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let mut redis = set_up_redis(&redis_url).await;
    flush_redis(&mut redis).await;

    // Start Anvil
    let anvil = TestAnvil::spawn().unwrap();
    let deployer = anvil.signer(0).unwrap();
    let registry_addr = anvil.deploy_world_id_registry(deployer).await.unwrap();
    let rpc_url = anvil.endpoint();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4105).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: redis_url.clone(),
        rate_limit_window_secs: Some(10), // 10 second window for testing
        rate_limit_max_requests: Some(3), // Only 3 requests allowed
    };

    let _gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4105).await;
    let base = "http://127.0.0.1:4105";

    let signer = PrivateKeySigner::random();
    let chain_id = 31337; // Anvil default chain ID

    // Create requests for the same leaf_index
    let leaf_index = 12345u64;

    // Request 1 - should succeed
    let signature1 = sign_insert_authenticator(
        leaf_index,
        address!("0x1111111111111111111111111111111111111111"),
        0,
        U256::from(100),
        U256::from(2),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let req1 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0x1111111111111111111111111111111111111111"),
        pubkey_id: 0,
        new_authenticator_pubkey: U256::from(100),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(2),
        signature: signature1.to_vec(),
        nonce: U256::from(0),
    };

    let resp1 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&req1)
        .send()
        .await
        .unwrap();

    // First request should pass rate limit (but might fail validation/simulation)
    // We only care that it's not a 429
    assert_ne!(
        resp1.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "First request should not be rate limited"
    );

    // Request 2 - should succeed
    let signature2 = sign_insert_authenticator(
        leaf_index,
        address!("0x2222222222222222222222222222222222222222"),
        1,
        U256::from(200),
        U256::from(3),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let req2 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0x2222222222222222222222222222222222222222"),
        pubkey_id: 1,
        new_authenticator_pubkey: U256::from(200),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(3),
        signature: signature2.to_vec(),
        nonce: U256::from(0),
    };

    let resp2 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&req2)
        .send()
        .await
        .unwrap();

    assert_ne!(
        resp2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Second request should not be rate limited"
    );

    // Request 3 - should succeed
    let signature3 = sign_insert_authenticator(
        leaf_index,
        address!("0x3333333333333333333333333333333333333333"),
        2,
        U256::from(300),
        U256::from(4),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let req3 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0x3333333333333333333333333333333333333333"),
        pubkey_id: 2,
        new_authenticator_pubkey: U256::from(300),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(4),
        signature: signature3.to_vec(),
        nonce: U256::from(0),
    };

    let resp3 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&req3)
        .send()
        .await
        .unwrap();

    assert_ne!(
        resp3.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Third request should not be rate limited"
    );

    // Request 4 - should be rate limited (exceeds limit of 3)
    let signature4 = sign_insert_authenticator(
        leaf_index,
        address!("0x4444444444444444444444444444444444444444"),
        3,
        U256::from(400),
        U256::from(5),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let req4 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0x4444444444444444444444444444444444444444"),
        pubkey_id: 3,
        new_authenticator_pubkey: U256::from(400),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(5),
        signature: signature4.to_vec(),
        nonce: U256::from(0),
    };

    let resp4 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&req4)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp4.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Fourth request should be rate limited"
    );

    let error_body: serde_json::Value = resp4.json().await.unwrap();
    assert_eq!(error_body["code"], "rate_limit_exceeded");
    assert!(
        error_body["message"]
            .as_str()
            .unwrap()
            .contains("maximum 3 requests per 10 seconds")
    );
}

#[tokio::test]
async fn test_rate_limit_different_leaf_indexes() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let mut redis = set_up_redis(&redis_url).await;
    flush_redis(&mut redis).await;

    // Start Anvil
    let anvil = TestAnvil::spawn().unwrap();
    let deployer = anvil.signer(0).unwrap();
    let registry_addr = anvil.deploy_world_id_registry(deployer).await.unwrap();
    let rpc_url = anvil.endpoint();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4106).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: redis_url.clone(),
        rate_limit_window_secs: Some(10),
        rate_limit_max_requests: Some(2), // Only 2 requests per leaf_index
    };

    let _gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4106).await;
    let base = "http://127.0.0.1:4106";

    let signer = PrivateKeySigner::random();
    let chain_id = 31337;

    // Send 2 requests for leaf_index 1000
    for i in 0..2u32 {
        let signature = sign_insert_authenticator(
            1000,
            Address::from([i as u8; 20]),
            i as u8,
            U256::from(100 + i),
            U256::from(2 + i as u64),
            U256::from(0),
            &signer,
            chain_id,
            registry_addr,
        )
        .await;

        let req = InsertAuthenticatorRequest {
            leaf_index: 1000,
            new_authenticator_address: Address::from([i as u8; 20]),
            pubkey_id: i,
            new_authenticator_pubkey: U256::from(100 + i),
            old_offchain_signer_commitment: U256::from(1),
            new_offchain_signer_commitment: U256::from(2 + i as u64),
            signature: signature.to_vec(),
            nonce: U256::from(0),
        };

        let resp = client
            .post(format!("{base}/insert-authenticator"))
            .json(&req)
            .send()
            .await
            .unwrap();

        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // Send 2 requests for leaf_index 2000 (different leaf_index)
    for i in 0..2u32 {
        let signature = sign_insert_authenticator(
            2000,
            Address::from([10 + i as u8; 20]),
            i as u8,
            U256::from(200 + i),
            U256::from(3 + i as u64),
            U256::from(0),
            &signer,
            chain_id,
            registry_addr,
        )
        .await;

        let req = InsertAuthenticatorRequest {
            leaf_index: 2000,
            new_authenticator_address: Address::from([10 + i as u8; 20]),
            pubkey_id: i,
            new_authenticator_pubkey: U256::from(200 + i),
            old_offchain_signer_commitment: U256::from(1),
            new_offchain_signer_commitment: U256::from(3 + i as u64),
            signature: signature.to_vec(),
            nonce: U256::from(0),
        };

        let resp = client
            .post(format!("{base}/insert-authenticator"))
            .json(&req)
            .send()
            .await
            .unwrap();

        // Should not be rate limited because it's a different leaf_index
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Different leaf_index should have separate rate limit"
        );
    }

    // Now send one more to leaf_index 1000 - should be rate limited
    let signature_extra = sign_insert_authenticator(
        1000,
        address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        5,
        U256::from(500),
        U256::from(10),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let req = InsertAuthenticatorRequest {
        leaf_index: 1000,
        new_authenticator_address: address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        pubkey_id: 5,
        new_authenticator_pubkey: U256::from(500),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(10),
        signature: signature_extra.to_vec(),
        nonce: U256::from(0),
    };

    let resp = client
        .post(format!("{base}/insert-authenticator"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Third request for leaf_index 1000 should be rate limited"
    );
}

#[tokio::test]
async fn test_rate_limit_sliding_window() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let mut redis = set_up_redis(&redis_url).await;
    flush_redis(&mut redis).await;

    // Start Anvil
    let anvil = TestAnvil::spawn().unwrap();
    let deployer = anvil.signer(0).unwrap();
    let registry_addr = anvil.deploy_world_id_registry(deployer).await.unwrap();
    let rpc_url = anvil.endpoint();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4107).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: redis_url.clone(),
        rate_limit_window_secs: Some(3), // 3 second window for faster testing
        rate_limit_max_requests: Some(2),
    };

    let _gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4107).await;
    let base = "http://127.0.0.1:4107";

    let signer = PrivateKeySigner::random();
    let chain_id = 31337;
    let leaf_index = 5000u64;

    // Send 2 requests (fill the quota)
    for i in 0..2u32 {
        let signature = sign_insert_authenticator(
            leaf_index,
            Address::from([i as u8; 20]),
            i as u8,
            U256::from(100 + i),
            U256::from(2 + i as u64),
            U256::from(0),
            &signer,
            chain_id,
            registry_addr,
        )
        .await;

        let req = InsertAuthenticatorRequest {
            leaf_index,
            new_authenticator_address: Address::from([i as u8; 20]),
            pubkey_id: i,
            new_authenticator_pubkey: U256::from(100 + i),
            old_offchain_signer_commitment: U256::from(1),
            new_offchain_signer_commitment: U256::from(2 + i as u64),
            signature: signature.to_vec(),
            nonce: U256::from(0),
        };

        let resp = client
            .post(format!("{base}/insert-authenticator"))
            .json(&req)
            .send()
            .await
            .unwrap();

        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // Third request should be rate limited
    let signature3 = sign_insert_authenticator(
        leaf_index,
        address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        3,
        U256::from(300),
        U256::from(5),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let req3 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        pubkey_id: 3,
        new_authenticator_pubkey: U256::from(300),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(5),
        signature: signature3.to_vec(),
        nonce: U256::from(0),
    };

    let resp3 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&req3)
        .send()
        .await
        .unwrap();

    assert_eq!(resp3.status(), StatusCode::TOO_MANY_REQUESTS);

    // Wait for the window to expire (3 seconds + buffer)
    tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

    // Now the request should succeed (old entries removed from window)
    let signature4 = sign_insert_authenticator(
        leaf_index,
        address!("0xcccccccccccccccccccccccccccccccccccccccc"),
        4,
        U256::from(400),
        U256::from(6),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let req4 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0xcccccccccccccccccccccccccccccccccccccccc"),
        pubkey_id: 4,
        new_authenticator_pubkey: U256::from(400),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(6),
        signature: signature4.to_vec(),
        nonce: U256::from(0),
    };

    let resp4 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&req4)
        .send()
        .await
        .unwrap();

    assert_ne!(
        resp4.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "After window expiration, requests should be allowed again"
    );
}

#[tokio::test]
async fn test_rate_limit_multiple_endpoints() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let mut redis = set_up_redis(&redis_url).await;
    flush_redis(&mut redis).await;

    // Start Anvil
    let anvil = TestAnvil::spawn().unwrap();
    let deployer = anvil.signer(0).unwrap();
    let registry_addr = anvil.deploy_world_id_registry(deployer).await.unwrap();
    let rpc_url = anvil.endpoint();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4108).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: redis_url.clone(),
        rate_limit_window_secs: Some(10),
        rate_limit_max_requests: Some(3),
    };

    let _gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4108).await;
    let base = "http://127.0.0.1:4108";

    let signer = PrivateKeySigner::random();
    let chain_id = 31337;
    let leaf_index = 7000u64;

    // Send insert request
    let insert_signature = sign_insert_authenticator(
        leaf_index,
        address!("0x1111111111111111111111111111111111111111"),
        0,
        U256::from(100),
        U256::from(2),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let insert_req = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0x1111111111111111111111111111111111111111"),
        pubkey_id: 0,
        new_authenticator_pubkey: U256::from(100),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(2),
        signature: insert_signature.to_vec(),
        nonce: U256::from(0),
    };

    let resp1 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&insert_req)
        .send()
        .await
        .unwrap();
    assert_ne!(resp1.status(), StatusCode::TOO_MANY_REQUESTS);

    // Send update request for same leaf_index
    let update_req = UpdateAuthenticatorRequest {
        leaf_index,
        old_authenticator_address: address!("0x2222222222222222222222222222222222222222"),
        new_authenticator_address: address!("0x3333333333333333333333333333333333333333"),
        pubkey_id: 1,
        new_authenticator_pubkey: U256::from(200),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(3),
        signature: {
            let typed_data = UpdateAuthenticatorTypedData {
                leafIndex: leaf_index,
                oldAuthenticatorAddress: address!("0x2222222222222222222222222222222222222222"),
                newAuthenticatorAddress: address!("0x3333333333333333333333333333333333333333"),
                pubkeyId: 1,
                newAuthenticatorPubkey: U256::from(200),
                newOffchainSignerCommitment: U256::from(3),
                nonce: U256::from(0),
            };
            let domain = alloy::sol_types::eip712_domain! {
                name: "WorldIDRegistry",
                version: "1.0",
                chain_id: chain_id,
                verifying_contract: registry_addr,
            };
            let hash = typed_data.eip712_signing_hash(&domain);
            let sig = signer.sign_hash(&hash).await.unwrap();
            Bytes::from(sig.as_bytes()).to_vec()
        },
        nonce: U256::from(0),
    };

    let resp2 = client
        .post(format!("{base}/update-authenticator"))
        .json(&update_req)
        .send()
        .await
        .unwrap();
    assert_ne!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

    // Send another insert request for same leaf_index
    let insert_signature2 = sign_insert_authenticator(
        leaf_index,
        address!("0x4444444444444444444444444444444444444444"),
        2,
        U256::from(300),
        U256::from(4),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let insert_req2 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0x4444444444444444444444444444444444444444"),
        pubkey_id: 2,
        new_authenticator_pubkey: U256::from(300),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(4),
        signature: insert_signature2.to_vec(),
        nonce: U256::from(0),
    };

    let resp3 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&insert_req2)
        .send()
        .await
        .unwrap();
    assert_ne!(resp3.status(), StatusCode::TOO_MANY_REQUESTS);

    // Fourth request (any endpoint) should be rate limited
    let insert_signature3 = sign_insert_authenticator(
        leaf_index,
        address!("0x5555555555555555555555555555555555555555"),
        3,
        U256::from(400),
        U256::from(5),
        U256::from(0),
        &signer,
        chain_id,
        registry_addr,
    )
    .await;

    let insert_req3 = InsertAuthenticatorRequest {
        leaf_index,
        new_authenticator_address: address!("0x5555555555555555555555555555555555555555"),
        pubkey_id: 3,
        new_authenticator_pubkey: U256::from(400),
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(5),
        signature: insert_signature3.to_vec(),
        nonce: U256::from(0),
    };

    let resp4 = client
        .post(format!("{base}/insert-authenticator"))
        .json(&insert_req3)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp4.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Rate limit should apply across all endpoints for the same leaf_index"
    );
}
