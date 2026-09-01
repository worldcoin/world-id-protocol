#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::common::{TestSetup, query_count};

use std::time::Duration;

use alloy::primitives::{Address, U256, address};
use eddsa_babyjubjub::EdDSAPrivateKey;
use http::StatusCode;
use sqlx::PgPool;
use world_id_indexer::config::{
    Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode, TreeCacheConfig,
};
use world_id_services_common::ProviderArgs;

fn random_pubkey() -> U256 {
    let sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    U256::from_le_slice(&sk.public().to_compressed_bytes().unwrap())
}

fn indexer_config(setup: &TestSetup, http_addr: &str) -> GlobalConfig {
    let temp_cache_path =
        std::env::temp_dir().join(format!("test_cache_{}.mmap", uuid::Uuid::new_v4()));
    GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
                tree_max_block_age: 1000,
                blockchain_poll_interval_ms: 1000,
                max_concurrent_log_requests: 1,
            },
            http_config: HttpConfig {
                http_addr: http_addr.parse().unwrap(),
                db_poll_interval_secs: 1,
                request_timeout_secs: 10,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        provider: ProviderArgs::new().with_http_urls([setup.rpc_url()]),
        registry_address: setup.registry_address,
        tree_cache: TreeCacheConfig {
            cache_file_path: temp_cache_path.to_str().unwrap().to_string(),
            tree_depth: 30,
            http_cache_refresh_interval_secs: 30,
        },
    }
}

async fn wait_for_accounts(pool: &PgPool, expected: i64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(pool).await;
        if c >= expected {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for backfill; count {c}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Waits until the indexer has committed the `AccountRecovered` event for `leaf_index`.
async fn wait_for_recovery_indexed(pool: &PgPool, leaf_index: i64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let (count,): (i64,) = sqlx::query_as(
            "select count(*) from world_id_registry_events \
             where event_type = 'account_recovered' and leaf_index = $1",
        )
        .bind(leaf_index)
        .fetch_one(pool)
        .await
        .unwrap();
        if count >= 1 {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for AccountRecovered to be indexed for leaf {leaf_index}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn packed_account(host_url: &str, auth_addr: Address) -> (StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{host_url}/packed-account"))
        .json(&serde_json::json!({ "authenticator_address": auth_addr }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap())
}

fn packed_data(json: &serde_json::Value) -> U256 {
    json["packed_account_data"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// Tests the packed_account endpoint that maps authenticator addresses to account indices
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_packed_account_endpoint() {
    let setup = TestSetup::new().await;
    let auth_addr = address!("0x0000000000000000000000000000000000000011");

    // Create an account with a specific authenticator address
    setup.create_account(auth_addr, random_pubkey(), 1).await;

    let global_config = indexer_config(&setup, "0.0.0.0:8083");
    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

    wait_for_accounts(&setup.pool, 1).await;
    TestSetup::wait_for_health("http://127.0.0.1:8083").await;

    // Test successful lookup: account index 1 maps to packed account index of 1
    let (status, json) = packed_account("http://127.0.0.1:8083", auth_addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["packed_account_data"].as_str().unwrap(), "0x1");

    // Test non-existent authenticator address
    let (status, json) = packed_account(
        "http://127.0.0.1:8083",
        address!("0x0000000000000000000000000000000000000099"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"].as_str().unwrap(), "account_does_not_exist");

    indexer_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_packed_account_rejects_authenticator_revoked_by_recovery() {
    let setup = TestSetup::new().await;
    let host = "http://127.0.0.1:8087";
    let leaf_index = 1u64;

    let recovery_agent = setup._anvil.signer(1).unwrap();
    let old_auth_addr = address!("0x0000000000000000000000000000000000000011");
    let new_auth_addr = address!("0x0000000000000000000000000000000000000022");
    let old_commitment = U256::from(1);
    let new_commitment = U256::from(2);

    setup
        .create_account_with_recovery_agent(
            old_auth_addr,
            random_pubkey(),
            old_commitment.to::<u64>(),
            recovery_agent.address(),
        )
        .await;

    let global_config = indexer_config(&setup, "0.0.0.0:8087");
    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

    wait_for_accounts(&setup.pool, 1).await;
    TestSetup::wait_for_health(host).await;

    // Before recovery the authenticator resolves normally.
    let (status, json) = packed_account(host, old_auth_addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(packed_data(&json), U256::from(leaf_index));

    setup
        .recover_account(
            leaf_index,
            new_auth_addr,
            random_pubkey(),
            old_commitment,
            new_commitment,
            &recovery_agent,
        )
        .await;
    wait_for_recovery_indexed(&setup.pool, leaf_index as i64).await;

    let (status, json) = packed_account(host, old_auth_addr).await;
    assert_eq!(status, StatusCode::BAD_REQUEST); // after recovery, the old authenticator is revoked
    assert_eq!(json["code"].as_str().unwrap(), "account_does_not_exist");

    // the other authenticator works
    let (status, json) = packed_account(host, new_auth_addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        packed_data(&json),
        (U256::from(1) << 224) | U256::from(leaf_index)
    );

    indexer_task.abort();
}
