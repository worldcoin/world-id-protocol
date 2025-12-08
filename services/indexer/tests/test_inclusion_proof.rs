#![cfg(feature = "integration-tests")]
mod common;

use std::time::Duration;

use alloy::primitives::{address, U256};
use common::{query_count, TestSetup, RECOVERY_ADDRESS};
use http::StatusCode;
use serial_test::serial;
use sqlx::types::Json;
use world_id_core::EdDSAPrivateKey;
use world_id_indexer::config::{Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_backfill_and_live_sync() {
    let setup = TestSetup::new().await;
    let sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk = sk.public().to_compressed_bytes().unwrap();
    let pk = U256::from_le_slice(&pk);

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000011"),
            pk,
            1,
        )
        .await;
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000012"),
            U256::from(12),
            2,
        )
        .await;

    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8080".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
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

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000013"),
            U256::from(13),
            3,
        )
        .await;
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000014"),
            U256::from(14),
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
#[cfg(feature = "integration-tests")]
#[serial]
async fn test_insertion_cycle_and_avoids_race_condition() {
    let setup = TestSetup::new().await;

    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::HttpOnly {
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8082".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
    };

    let http_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
    });

    TestSetup::wait_for_health("http://127.0.0.1:8082").await;

    sqlx::query(
        r#"insert into accounts
        (leaf_index, recovery_address, authenticator_addresses, authenticator_pubkeys, offchain_signer_commitment)
        values ($1, $2, $3, $4, $5)"#,
    )
    .bind("1")
    .bind(RECOVERY_ADDRESS.to_string())
    .bind(Json(vec![
        "0x0000000000000000000000000000000000000011".to_string()
    ]))
    .bind(Json(vec!["11".to_string()]))
    .bind("99")
    .execute(&setup.pool)
    .await
    .unwrap();

    sqlx::query(
        r#"insert into commitment_update_events
        (leaf_index, event_type, new_commitment, block_number, tx_hash, log_index)
        values ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind("1")
    .bind("created")
    .bind("99")
    .bind(1i64)
    .bind("0x0000000000000000000000000000000000000000000000000000000000000001")
    .bind(0i64)
    .execute(&setup.pool)
    .await
    .unwrap();

    let client = reqwest::Client::new();

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
    assert_eq!(resp.status(), StatusCode::LOCKED);

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
    // leaf_index is now serialized as hex string
    assert_eq!(proof["leaf_index"].as_str().unwrap(), "0x1");

    http_task.abort();
}
