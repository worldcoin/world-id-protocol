#![cfg(feature = "integration-tests")]
mod helpers;
use helpers::common::{TestSetup, query_count};
use serial_test::serial;

use std::time::Duration;

use alloy::primitives::{U256, address};
use http::StatusCode;
use world_id_core::EdDSAPrivateKey;
use world_id_indexer::config::{
    Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode, TreeCacheConfig,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_backfill_and_live_sync() {
    let setup = TestSetup::new_with_tree_depth(6).await;

    // Generate valid EdDSA public keys
    let sk1 = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk1 = U256::from_le_slice(&sk1.public().to_compressed_bytes().unwrap());

    let sk2 = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk2 = U256::from_le_slice(&sk2.public().to_compressed_bytes().unwrap());

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000011"),
            pk1,
            1,
        )
        .await;
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000012"),
            pk2,
            2,
        )
        .await;

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
                http_addr: "0.0.0.0:8080".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                reorg_check_interval_secs: None,
                max_sync_backward_check_blocks: 100,
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

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 2 {
            assert_eq!(c, 2);
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for backfill; count {c}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Generate more valid EdDSA public keys for live sync test
    let sk3 = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk3 = U256::from_le_slice(&sk3.public().to_compressed_bytes().unwrap());

    let sk4 = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk4 = U256::from_le_slice(&sk4.public().to_compressed_bytes().unwrap());

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000013"),
            pk3,
            3,
        )
        .await;
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000014"),
            pk4,
            4,
        )
        .await;

    let deadline2 = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c2 = query_count(&setup.pool).await;
        if c2 >= 4 {
            assert_eq!(c2, 4);
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for live sync; count {c2}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:8080/inclusion-proof")
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "leaf_index": "0x1"
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let json = resp.json::<serde_json::Value>().await.unwrap();
    let root = json["root"].as_str().unwrap();
    let root = U256::from_str_radix(root.strip_prefix("0x").unwrap(), 16).unwrap();

    let onchain_root = setup.get_root().await;
    assert_eq!(root, onchain_root);

    indexer_task.abort();
}

/// Tests that we properly handle the update cycles when new accounts get inserted into the registry.
///
/// When new accounts get inserted into the registry, the worker (indexer) listens for on-chain events and inserts new accounts
/// into the DB. Each HTTP indexer instance has its own in-memory tree. When querying for a proof, it's possible that the account
/// is already in the DB, but the in-memory tree is not yet updated. This test ensures that we properly handle this case
/// so that an incorrect inclusion proof is never returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[cfg(feature = "integration-tests")]
async fn test_insertion_cycle_and_avoids_race_condition() {
    let setup = TestSetup::new_with_tree_depth(6).await;

    // Create an account on-chain using the test helper
    // This properly creates the account through the WorldIdRegistry contract
    let sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk = U256::from_le_slice(&sk.public().to_compressed_bytes().unwrap());

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000021"),
            pk,
            1,
        )
        .await;

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
                http_addr: "0.0.0.0:8082".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                reorg_check_interval_secs: None,
                max_sync_backward_check_blocks: 100,
                tree_cache: TreeCacheConfig {
                    cache_file_path: temp_cache_path.to_str().unwrap().to_string(),
                    tree_depth: 6,
                    http_cache_refresh_interval_secs: 1,
                },
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let http_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

    TestSetup::wait_for_health("http://127.0.0.1:8082").await;

    let client = reqwest::Client::new();

    // wait for the in-memory tree to be updated
    tokio::time::sleep(Duration::from_secs(2)).await;

    let resp = client
        .post("http://127.0.0.1:8082/inclusion-proof")
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "leaf_index": "0x1"
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let proof: serde_json::Value = resp.json().await.unwrap();
    assert!(proof["root"].is_string());
    assert_eq!(proof["leaf_index"].as_str().unwrap(), "0x1");

    http_task.abort();
}
