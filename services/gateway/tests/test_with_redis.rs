#![cfg(feature = "integration-tests")]

use ::common::{ProviderArgs, SignerArgs};
use alloy::{
    primitives::{Address, U256, address},
    signers::local::PrivateKeySigner,
};
use redis::{AsyncTypedCommands, IntegerReplyOrNoOp, aio::ConnectionManager};
use reqwest::{Client, StatusCode};
use test_utils::anvil::TestAnvil;
use world_id_core::api_types::GatewayStatusResponse;
use world_id_gateway::{GatewayConfig, spawn_gateway_for_tests};

use crate::common::{wait_for_finalized, wait_http_ready};

mod common;

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // FIXME

async fn set_up_redis(redis_url: &str) -> ConnectionManager {
    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    client.get_connection_manager().await.unwrap()
}

async fn flush_redis(redis: &mut ConnectionManager) {
    redis.flushdb().await.unwrap();
}

#[tokio::test]
async fn redis_integration() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let mut redis = set_up_redis(&redis_url).await;
    flush_redis(&mut redis).await;

    // Start Anvil
    let anvil = TestAnvil::spawn().unwrap();
    let deployer = anvil.signer(0).unwrap();
    let registry_addr = anvil.deploy_world_id_registry(deployer).await.unwrap();
    let rpc_url = anvil.endpoint();

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4103).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: Some(redis_url),
    };

    let gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4103).await;
    let base = "http://127.0.0.1:4103";

    // Create a test request
    let body = world_id_core::api_types::CreateAccountRequest {
        recovery_address: Some(wallet_addr),
        authenticator_addresses: vec![address!("0x1111111111111111111111111111111111111111")],
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
    let request_id = accepted.request_id.clone();

    // Verify the request was stored in Redis
    let redis_key = format!("gateway:request:{}", request_id);
    let stored = redis.get(&redis_key).await.unwrap().unwrap();
    let stored_data: serde_json::Value =
        serde_json::from_str(&stored).expect("Failed to parse JSON");

    assert_eq!(stored_data["kind"], "create_account");
    assert_eq!(stored_data["status"]["state"], "queued");

    // Check that TTL is set (should be ~86400 seconds)
    match redis.ttl(&redis_key).await.unwrap() {
        IntegerReplyOrNoOp::IntegerReply(ttl) => {
            assert!(ttl > 86000 && ttl <= 86400);
        }
        _ => panic!("TTL should be set to 24 hours"),
    };

    // Wait for the request to be processed
    let tx_hash = wait_for_finalized(&client, base, &request_id).await;
    assert!(!tx_hash.is_empty());

    // Verify status was updated in Redis
    let updated = redis.get(&redis_key).await.unwrap().unwrap();
    let updated_data: serde_json::Value = serde_json::from_str(&updated).unwrap();

    assert_eq!(updated_data["status"]["state"], "finalized");
    assert!(updated_data["status"]["tx_hash"].is_string());

    // Cleanup
    let _ = gw.shutdown().await;
}
