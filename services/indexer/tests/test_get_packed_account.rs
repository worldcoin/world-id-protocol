#![cfg(feature = "integration-tests")]

mod common;

use std::time::Duration;

use alloy::primitives::{U256, address};
use common::{TestSetup, query_count};
use http::StatusCode;
use serial_test::serial;
use world_id_core::EdDSAPrivateKey;
use world_id_indexer::config::{
    Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode, TreeCacheConfig,
};

/// Tests the packed_account endpoint that maps authenticator addresses to account indices
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_packed_account_endpoint() {
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8083".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: TreeCacheConfig {
            cache_file_path: temp_cache_path.to_str().unwrap().to_string(),
            tree_depth: 6,
            dense_tree_prefix_depth: 2,
            http_cache_refresh_interval_secs: 30,
        },
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
    });

    // Add a small delay to let initialization start
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("Indexer task spawned, waiting for backfill...");

    // Wait for account to be indexed
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        println!(
            "Current account count: {} (elapsed: {:?})",
            c,
            deadline.saturating_duration_since(std::time::Instant::now())
        );
        if c >= 1 {
            println!("Account found! Backfill complete.");
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for backfill; count {c}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    TestSetup::wait_for_health("http://127.0.0.1:8083").await;

    let client = reqwest::Client::new();

    // Test successful lookup
    let resp = client
        .post("http://127.0.0.1:8083/packed-account")
        .json(&serde_json::json!({
            "authenticator_address": auth_addr
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    let packed_account_data = json["packed_account_data"].as_str().unwrap();

    // Account index 1 should map to packed account index of 1
    assert_eq!(packed_account_data, "0x1");

    // Test non-existent authenticator address
    let resp = client
        .post("http://127.0.0.1:8083/packed-account")
        .json(&serde_json::json!({
            "authenticator_address": "0x0000000000000000000000000000000000000099"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["code"].as_str().unwrap(), "account_does_not_exist");

    indexer_task.abort();
}
