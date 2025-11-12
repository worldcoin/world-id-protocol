#[allow(dead_code)]
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{address, Address, U256};
use alloy::providers::ProviderBuilder;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use test_utils::anvil::TestAnvil;
use world_id_core::account_registry::AccountRegistry;
use world_id_indexer::config::{GlobalConfig, HttpConfig, IndexerConfig};

const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");
const TEST_DB_NAME: &str = "indexer_tests";

async fn setup_test_database() -> String {
    let base_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base_url)
        .await
        .unwrap();

    let _ = pool
        .execute(format!("DROP DATABASE IF EXISTS {TEST_DB_NAME}").as_str())
        .await;
    pool.execute(format!("CREATE DATABASE {TEST_DB_NAME}").as_str())
        .await
        .unwrap();

    let test_db_url = if let Some(idx) = base_url.rfind('/') {
        format!("{}/{}", &base_url[..idx], TEST_DB_NAME)
    } else {
        panic!("Invalid database URL format: {base_url}");
    };

    test_db_url
}

async fn query_count(pool: &PgPool) -> i64 {
    let rec: (i64,) = sqlx::query_as("select count(*) from accounts")
        .fetch_one(pool)
        .await
        .unwrap();
    rec.0
}

async fn cleanup_test_database() {
    let base_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".to_string());

    if let Ok(pool) = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base_url)
        .await
    {
        let _ = pool
            .execute(format!("DROP DATABASE IF EXISTS {TEST_DB_NAME}").as_str())
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "integration-tests")]
async fn e2e_backfill_and_live_sync() {
    use world_id_indexer::config::{Environment, RunMode};

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let db_url = setup_test_database().await;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect to test database");

    world_id_indexer::init_db(&pool)
        .await
        .expect("failed to initialize test database");

    // Start local anvil instance and deploy the AccountRegistry
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    let deployer = anvil
        .signer(0)
        .expect("failed to obtain deployer signer from anvil");
    let registry_address = anvil
        .deploy_account_registry(deployer.clone())
        .await
        .expect("failed to deploy AccountRegistry");
    let rpc_url = anvil.endpoint().to_string();
    let ws_url = anvil.ws_endpoint().to_string();

    let registry_contract = AccountRegistry::new(
        registry_address,
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.clone()))
            .connect_http(rpc_url.parse().expect("invalid anvil endpoint url")),
    );

    // Pre-insert a couple accounts before starting indexer (backfill test)
    let pre_accounts = [
        (
            address!("0x0000000000000000000000000000000000000011"),
            11u64,
            1u64,
        ),
        (
            address!("0x0000000000000000000000000000000000000012"),
            12u64,
            2u64,
        ),
    ];

    for (auth_addr, pubkey, commitment) in pre_accounts {
        registry_contract
            .createAccount(
                RECOVERY_ADDRESS,
                vec![auth_addr],
                vec![U256::from(pubkey)],
                U256::from(commitment),
            )
            .send()
            .await
            .expect("failed to submit createAccount transaction")
            .get_receipt()
            .await
            .expect("createAccount transaction failed");
    }

    let indexer_config = IndexerConfig {
        rpc_url,
        ws_url,
        registry_address,
        start_block: 0,
        batch_size: 1000,
    };

    let http_config = HttpConfig {
        http_addr: "0.0.0.0:8080".parse().unwrap(),
        db_poll_interval_secs: 1,
        sanity_check_interval_secs: None,
        rpc_url: None,
        registry_address: None,
    };

    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config,
            http_config,
        },
        db_url: db_url.to_string(),
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
    });

    // Allow time for backfill (poll until >= 2)
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&pool).await;
        println!("Backfill count: {c}");
        if c >= 2 {
            assert!(c == 2, "backfill count is not 2");
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for backfill; count {c}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Live insert more accounts while WS stream is active
    let live_accounts = [
        (
            address!("0x0000000000000000000000000000000000000013"),
            13u64,
            3u64,
        ),
        (
            address!("0x0000000000000000000000000000000000000014"),
            14u64,
            4u64,
        ),
    ];

    for (auth_addr, pubkey, commitment) in live_accounts {
        registry_contract
            .createAccount(
                RECOVERY_ADDRESS,
                vec![auth_addr],
                vec![U256::from(pubkey)],
                U256::from(commitment),
            )
            .send()
            .await
            .expect("failed to submit live createAccount transaction")
            .get_receipt()
            .await
            .expect("live createAccount transaction failed");
    }

    // Wait for live sync
    let deadline2 = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c2 = query_count(&pool).await;
        println!("Live sync count: {c2}");
        if c2 >= 4 {
            assert!(c2 == 4, "live sync count is not 4");
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for live sync; count {c2}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Verify proof endpoint is working
    let client = reqwest::Client::builder().build().unwrap();
    let base = "http://127.0.0.1:8080";
    let resp = client.get(format!("{base}/proof/1")).send().await;

    assert!(resp.is_ok(), "proof request failed");
    let resp = resp.unwrap();
    assert!(resp.status().is_success(), "proof request failed");

    tracing::info!("proof response: {:?}", resp.text().await.unwrap());

    // Cleanup
    indexer_task.abort();
    drop(anvil);
    drop(pool); // Close all connections to the test database
    cleanup_test_database().await;
}
