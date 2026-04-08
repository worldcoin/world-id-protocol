#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::common::{TestSetup, query_count};

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, U256, address},
    providers::{Provider, ProviderBuilder},
};
use http::StatusCode;
use world_id_core::{
    EdDSAPrivateKey,
    api_types::UpdateRecoveryAgentRequest,
    world_id_registry::{
        WorldIdRegistry, domain as ag_domain, sign_initiate_recovery_agent_update,
    },
};
use world_id_indexer::config::{
    Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode, TreeCacheConfig,
};
use world_id_services_common::ProviderArgs;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_pending_recovery_agent_endpoint() {
    let setup = TestSetup::new().await;
    let signer = setup
        ._anvil
        .signer(1)
        .expect("failed to obtain funded signer");
    let auth_addr: Address = signer.address();
    let sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let pk = sk.public().to_compressed_bytes().unwrap();
    let pk = U256::from_le_slice(&pk);

    setup.create_account(auth_addr, pk, 1).await;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer.clone()))
        .connect_http(setup.rpc_url().parse().unwrap());
    let registry = WorldIdRegistry::new(setup.registry_address, provider.clone());
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, setup.registry_address);

    let leaf_index = 1;
    let new_recovery_agent = address!("0x000000000000000000000000000000000000beef");
    let nonce = U256::ZERO;
    let signature = sign_initiate_recovery_agent_update(
        &signer,
        leaf_index,
        new_recovery_agent,
        nonce,
        &domain,
    )
    .unwrap();

    let request = UpdateRecoveryAgentRequest {
        leaf_index,
        new_recovery_agent,
        signature,
        nonce,
    };

    registry
        .initiateRecoveryAgentUpdate(
            request.leaf_index,
            request.new_recovery_agent,
            Bytes::copy_from_slice(&request.signature.as_bytes()),
            request.nonce,
        )
        .send()
        .await
        .expect("failed to submit initiateRecoveryAgentUpdate transaction")
        .get_receipt()
        .await
        .expect("initiateRecoveryAgentUpdate transaction failed");

    let pending_recovery_agent_update = registry
        .getPendingRecoveryAgentUpdate(leaf_index)
        .call()
        .await
        .unwrap();

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

    let resp = client
        .post("http://127.0.0.1:8086/pending-recovery-agent")
        .json(&serde_json::json!({
            "leaf_index": "0x1"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    let pending_recovery_agent = json["pending_recovery_agent"].as_str().unwrap();
    assert_eq!(
        pending_recovery_agent.to_lowercase(),
        format!("{new_recovery_agent}").to_lowercase()
    );

    let execute_after = json["execute_after"].as_str().unwrap();
    assert_eq!(
        execute_after.to_lowercase(),
        format!("0x{:x}", pending_recovery_agent_update.executeAfter).to_lowercase()
    );

    let resp = client
        .post("http://127.0.0.1:8086/pending-recovery-agent")
        .json(&serde_json::json!({
            "leaf_index": "0x0"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["code"].as_str().unwrap(), "invalid_leaf_index");

    let resp = client
        .post("http://127.0.0.1:8086/pending-recovery-agent")
        .json(&serde_json::json!({
            "leaf_index": "0xFF"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["code"].as_str().unwrap(), "account_does_not_exist");

    indexer_task.abort();
}
