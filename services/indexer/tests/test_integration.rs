use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{address, Address, U256};
use alloy::providers::ProviderBuilder;
use http::StatusCode;
use serial_test::serial;
use sqlx::types::Json;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use test_utils::anvil::TestAnvil;
use world_id_core::account_registry::AccountRegistry;
use world_id_indexer::config::{Environment, RunMode};
use world_id_indexer::config::{GlobalConfig, HttpConfig, IndexerConfig};

const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");
const TEST_DB_NAME: &str = "indexer_tests";

struct TestSetup {
    _anvil: TestAnvil,
    registry_address: Address,
    db_url: String,
    pool: PgPool,
}

impl TestSetup {
    async fn new() -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let db_url = Self::setup_test_database().await;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("failed to connect to test database");
        world_id_indexer::init_db(&pool)
            .await
            .expect("failed to initialize test database");

        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let deployer = anvil.signer(0).expect("failed to obtain deployer signer");
        let registry_address = anvil
            .deploy_account_registry(deployer)
            .await
            .expect("failed to deploy AccountRegistry");

        Self {
            _anvil: anvil,
            registry_address,
            db_url,
            pool,
        }
    }

    fn rpc_url(&self) -> String {
        self._anvil.endpoint().to_string()
    }

    fn ws_url(&self) -> String {
        self._anvil.ws_endpoint().to_string()
    }

    async fn create_account(&self, auth_addr: Address, pubkey: u64, commitment: u64) {
        let deployer = self
            ._anvil
            .signer(0)
            .expect("failed to get deployer signer");
        let registry = AccountRegistry::new(
            self.registry_address,
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(deployer))
                .connect_http(
                    self._anvil
                        .endpoint()
                        .parse()
                        .expect("invalid anvil endpoint url"),
                ),
        );
        registry
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

    async fn setup_test_database() -> String {
        let base_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://postgres:postgres@localhost:5432/postgres".to_string()
        });

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

    async fn cleanup_test_database() {
        let base_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://postgres:postgres@localhost:5432/postgres".to_string()
        });

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

    async fn wait_for_health(host_url: &str) {
        let client = reqwest::Client::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);

        loop {
            if let Ok(resp) = client.get(format!("{host_url}/health")).send().await {
                if resp.status().is_success() {
                    return;
                }
            }

            if std::time::Instant::now() > deadline {
                panic!("Timeout waiting for server health check at {host_url}");
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for TestSetup {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(Self::cleanup_test_database());
        });
    }
}

async fn query_count(pool: &PgPool) -> i64 {
    let rec: (i64,) = sqlx::query_as("select count(*) from accounts")
        .fetch_one(pool)
        .await
        .unwrap();
    rec.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "integration-tests")]
#[serial]
async fn e2e_backfill_and_live_sync() {
    use world_id_indexer::config::{Environment, RunMode};

    let setup = TestSetup::new().await;

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000011"),
            11,
            1,
        )
        .await;
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000012"),
            12,
            2,
        )
        .await;

    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                rpc_url: setup.rpc_url(),
                ws_url: setup.ws_url(),
                registry_address: setup.registry_address,
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8080".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                rpc_url: None,
                registry_address: None,
            },
        },
        db_url: setup.db_url.clone(),
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
            13,
            3,
        )
        .await;
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000014"),
            14,
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
        .get("http://127.0.0.1:8080/proof/1")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

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
                rpc_url: None,
                registry_address: None,
            },
        },
        db_url: setup.db_url.clone(),
    };

    let http_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
    });

    TestSetup::wait_for_health("http://127.0.0.1:8082").await;

    sqlx::query(
        r#"insert into accounts
        (account_index, recovery_address, authenticator_addresses, authenticator_pubkeys, offchain_signer_commitment)
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
        (account_index, event_type, new_commitment, block_number, tx_hash, log_index)
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
        .get("http://127.0.0.1:8082/proof/1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED);

    // wait for the in-memory tree to be updated
    tokio::time::sleep(Duration::from_secs(2)).await;

    let resp = client
        .get("http://127.0.0.1:8082/proof/1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let proof: serde_json::Value = resp.json().await.unwrap();
    assert!(proof["root"].is_string());
    assert_eq!(proof["account_id"].as_u64().unwrap(), 1);

    http_task.abort();
}
