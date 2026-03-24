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
use world_id_services_common::ProviderArgs;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_authenticator_pubkeys_returns_offchain_signer_commitment() {
    let setup = TestSetup::new().await;
    let sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk = sk.public().to_compressed_bytes().unwrap();
    let pk = U256::from_le_slice(&pk);

    let auth_addr = address!("0x0000000000000000000000000000000000000011");
    let commitment: u64 = 42;

    setup.create_account(auth_addr, pk, commitment).await;

    let temp_cache_path =
        std::env::temp_dir().join(format!("test_cache_{}.mmap", uuid::Uuid::new_v4()));
    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
                tree_max_block_age: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8086".parse().unwrap(),
                db_poll_interval_secs: 1,
                request_timeout_secs: 10,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        provider: ProviderArgs::new().with_http_urls([setup.rpc_url()]),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
        tree_cache: TreeCacheConfig {
            cache_file_path: temp_cache_path.to_str().unwrap().to_string(),
            tree_depth: 30,
            http_cache_refresh_interval_secs: 30,
        },
    };

    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

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

    TestSetup::wait_for_health("http://127.0.0.1:8086").await;

    let client = reqwest::Client::new();

    // Successful lookup returns authenticator pubkeys and offchain_signer_commitment
    let resp = client
        .post("http://127.0.0.1:8086/authenticator-pubkeys")
        .json(&serde_json::json!({
            "leaf_index": "0x1"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();

    let osc = json["offchain_signer_commitment"].as_str().unwrap();
    assert_eq!(osc, "0x2a");

    // authenticator_pubkeys must be present and non-empty
    let pubkeys = json["authenticator_pubkeys"]
        .as_array()
        .expect("authenticator_pubkeys should be an array");
    assert_eq!(pubkeys.len(), 1);
    assert!(pubkeys[0].is_string());

    // Zero leaf index is rejected
    let resp = client
        .post("http://127.0.0.1:8086/authenticator-pubkeys")
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
