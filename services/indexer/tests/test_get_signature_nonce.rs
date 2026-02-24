#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::common::{TestSetup, query_count};

use std::time::Duration;

use alloy::primitives::{U256, address};
use http::StatusCode;
use world_id_core::EdDSAPrivateKey;
use world_id_indexer::config::{
    Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode, TreeCacheConfig,
};

/// Tests the signature_nonce endpoint that retrieves signature nonces by account index
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signature_nonce_endpoint() {
    let setup = TestSetup::new().await;
    let sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk = sk.public().to_compressed_bytes().unwrap();
    let pk = U256::from_le_slice(&pk);

    let auth_addr = address!("0x0000000000000000000000000000000000000011");

    // Create an account with a specific authenticator address
    setup.create_account(auth_addr, pk, 1).await;

    let temp_cache_path =
        std::env::temp_dir().join(format!("test_cache_{}.mmap", uuid::Uuid::new_v4()));
    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8084".parse().unwrap(),
                db_poll_interval_secs: 1,
                request_timeout_secs: 10,
                sanity_check_interval_secs: None,
                tree_cache: TreeCacheConfig {
                    cache_file_path: temp_cache_path.to_str().unwrap().to_string(),
                    tree_depth: 6,
                    http_cache_refresh_interval_secs: 30,
                },
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

    // Wait for account to be indexed
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 1 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for backfill; count {c}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    TestSetup::wait_for_health("http://127.0.0.1:8084").await;

    let client = reqwest::Client::new();

    // Test successful lookup for account index 1
    let resp = client
        .post("http://127.0.0.1:8084/signature-nonce")
        .json(&serde_json::json!({
            "leaf_index": "0x1"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    let signature_nonce = json["signature_nonce"].as_str().unwrap();

    // New account should have nonce 0
    assert_eq!(signature_nonce, "0x0");

    // Test zero account index (should fail)
    let resp = client
        .post("http://127.0.0.1:8084/signature-nonce")
        .json(&serde_json::json!({
            "leaf_index": "0x0"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["code"].as_str().unwrap(), "invalid_leaf_index");

    indexer_task.abort();
}
