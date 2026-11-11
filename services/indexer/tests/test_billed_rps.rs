#![cfg(feature = "integration-tests")]
#![recursion_limit = "256"]

mod helpers;
use helpers::common::TestSetup;

use std::time::Duration;

use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider as _},
};
use http::StatusCode;
use world_id_indexer::config::{
    BillingConfig, Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode, TreeCacheConfig,
};
use world_id_primitives::{api_types::IndexerBilledRpsResponse, rp::RpId};
use world_id_services_common::ProviderArgs;
use world_id_test_utils::anvil::world_id_billing::WorldIDBilling;

fn config(setup: &TestSetup, run_mode: RunMode, billing: Option<BillingConfig>) -> GlobalConfig {
    let cache_path = std::env::temp_dir().join(format!("test_cache_{}.mmap", uuid::Uuid::new_v4()));
    GlobalConfig {
        environment: Environment::Development,
        run_mode,
        db_url: setup.db_url.clone(),
        provider: ProviderArgs::new().with_http_urls([setup.rpc_url()]),
        registry_address: setup.registry_address,
        tree_cache: TreeCacheConfig {
            cache_file_path: cache_path.to_str().unwrap().to_string(),
            tree_depth: 30,
            http_cache_refresh_interval_secs: 30,
        },
        billing,
    }
}

fn billing_config(address: Address, start_block: u64, confirmations: u64) -> BillingConfig {
    BillingConfig {
        address,
        start_block,
        confirmations,
        poll_interval: Duration::from_millis(200),
        max_sync_age_secs: 300,
    }
}

fn http_config(setup: &TestSetup, port: u16) -> HttpConfig {
    HttpConfig {
        verifier_address: setup.verifier_address,
        http_addr: format!("0.0.0.0:{port}").parse().unwrap(),
        db_poll_interval_secs: 1,
        request_timeout_secs: 10,
        sanity_check_interval_secs: None,
    }
}

async fn set_billed(provider: &DynProvider, billing: Address, rp_id: u64, billed: bool) {
    WorldIDBilling::new(billing, provider.clone())
        .setBilledRp(rp_id, billed)
        .send()
        .await
        .expect("setBilledRp should send")
        .with_timeout(Some(Duration::from_secs(10)))
        .get_receipt()
        .await
        .expect("setBilledRp should be mined");
}

/// Polls `GET /billing/billed-rps` until it reports `expected`.
async fn wait_for_billed_rps(url: &str, expected: &[u64]) -> IndexerBilledRpsResponse {
    let expected: Vec<RpId> = expected.iter().copied().map(RpId::new).collect();
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut last = None;
    while std::time::Instant::now() < deadline {
        let resp = client
            .get(format!("{url}/billing/billed-rps"))
            .send()
            .await
            .unwrap();
        if resp.status() == StatusCode::OK {
            let body: IndexerBilledRpsResponse = resp.json().await.unwrap();
            if body.billed_rp_ids == expected {
                return body;
            }
            last = Some(body);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("billed RPs never became {expected:?}; last response {last:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_billed_rps_follow_the_billing_contract_through_a_reorg() {
    let setup = TestSetup::new().await;
    let deployer = setup._anvil.signer(0).unwrap();
    let billing = setup
        ._anvil
        .deploy_world_id_billing(deployer, setup.verifier_address, setup.registry_address)
        .await
        .expect("failed to deploy WorldIDBilling")
        .billing;
    let provider = setup.provider();

    set_billed(&provider, billing, 7, true).await;
    set_billed(&provider, billing, 8, true).await;
    set_billed(&provider, billing, 8, false).await;

    let global_config = config(
        &setup,
        RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
                tree_max_block_age: 1000,
                blockchain_poll_interval_ms: 200,
                max_concurrent_log_requests: 1,
            },
            http_config: http_config(&setup, 8120),
        },
        Some(billing_config(billing, 0, 0)),
    );
    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });
    TestSetup::wait_for_health("http://127.0.0.1:8120").await;

    let body = wait_for_billed_rps("http://127.0.0.1:8120", &[7]).await;
    assert_eq!(body.chain_id, provider.get_chain_id().await.unwrap());
    assert_eq!(body.billing_contract, billing);
    assert!(body.synced_at > 0);

    // An RP billed on a fork the chain later abandons is dropped again.
    let snapshot: alloy::primitives::U256 = provider
        .raw_request("evm_snapshot".into(), ())
        .await
        .unwrap();
    set_billed(&provider, billing, 9, true).await;
    wait_for_billed_rps("http://127.0.0.1:8120", &[7, 9]).await;

    let reverted: bool = provider
        .raw_request("evm_revert".into(), (snapshot,))
        .await
        .unwrap();
    assert!(reverted);
    // Grow the new fork past the synced block, so its hash is checked against a different block.
    let _: () = provider
        .raw_request("anvil_mine".into(), (5u64,))
        .await
        .unwrap();
    wait_for_billed_rps("http://127.0.0.1:8120", &[7]).await;

    // The reverted fork's nonces are gone; a fresh provider reads the current one.
    let provider = setup.provider();
    set_billed(&provider, billing, 10, true).await;
    wait_for_billed_rps("http://127.0.0.1:8120", &[7, 10]).await;

    indexer_task.abort();
}

/// A reorganization of the start block itself drops the events synced from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_billed_rps_reorg_of_the_start_block() {
    let setup = TestSetup::new().await;
    let deployer = setup._anvil.signer(0).unwrap();
    let billing = setup
        ._anvil
        .deploy_world_id_billing(deployer, setup.verifier_address, setup.registry_address)
        .await
        .expect("failed to deploy WorldIDBilling")
        .billing;
    let provider = setup.provider();

    let snapshot: alloy::primitives::U256 = provider
        .raw_request("evm_snapshot".into(), ())
        .await
        .unwrap();
    // `setBilledRp` is mined in the next block, which the sync starts from.
    let start_block = provider.get_block_number().await.unwrap() + 1;
    set_billed(&provider, billing, 7, true).await;

    let global_config = config(
        &setup,
        RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
                tree_max_block_age: 1000,
                blockchain_poll_interval_ms: 200,
                max_concurrent_log_requests: 1,
            },
            http_config: http_config(&setup, 8122),
        },
        Some(billing_config(billing, start_block, 2)),
    );
    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });
    TestSetup::wait_for_health("http://127.0.0.1:8122").await;
    // The sync stays 2 blocks below the head.
    let _: () = provider
        .raw_request("anvil_mine".into(), (2u64,))
        .await
        .unwrap();
    wait_for_billed_rps("http://127.0.0.1:8122", &[7]).await;

    let reverted: bool = provider
        .raw_request("evm_revert".into(), (snapshot,))
        .await
        .unwrap();
    assert!(reverted);
    let _: () = provider
        .raw_request("anvil_mine".into(), (5u64,))
        .await
        .unwrap();
    wait_for_billed_rps("http://127.0.0.1:8122", &[]).await;

    indexer_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_billed_rps_unavailable_before_a_current_sync() {
    let setup = TestSetup::new().await;
    let unsynced = Address::repeat_byte(0xb1);

    let global_config = config(
        &setup,
        RunMode::HttpOnly {
            http_config: http_config(&setup, 8121),
        },
        Some(billing_config(unsynced, 0, 0)),
    );
    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });
    TestSetup::wait_for_health("http://127.0.0.1:8121").await;

    let resp = reqwest::get("http://127.0.0.1:8121/billing/billed-rps")
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["code"].as_str().unwrap(), "billing_not_synced");

    // A sync last current long ago is reported as stale rather than served.
    sqlx::query(
        "INSERT INTO billing_sync_checkpoints
             (billing_contract, chain_id, start_block, block_number, block_hash, synced_at)
         VALUES ($1, 31337, 0, 1, $2, 1)",
    )
    .bind(unsynced.as_slice())
    .bind([0u8; 32].as_slice())
    .execute(&setup.pool)
    .await
    .unwrap();
    let resp = reqwest::get("http://127.0.0.1:8121/billing/billed-rps")
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["code"].as_str().unwrap(), "billing_sync_stale");

    indexer_task.abort();
}
