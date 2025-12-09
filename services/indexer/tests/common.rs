#![allow(dead_code)]

use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{address, Address, U256};
use alloy::providers::ProviderBuilder;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use test_utils::anvil::TestAnvil;
use world_id_core::world_id_registry::WorldIDRegistry;

pub const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");
const TEST_DB_NAME: &str = "indexer_tests";

pub struct TestSetup {
    pub _anvil: TestAnvil,
    pub registry_address: Address,
    pub db_url: String,
    pub pool: PgPool,
}

impl TestSetup {
    pub async fn new() -> Self {
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
            .expect("failed to deploy WorldIDRegistry");

        Self {
            _anvil: anvil,
            registry_address,
            db_url,
            pool,
        }
    }

    pub fn rpc_url(&self) -> String {
        self._anvil.endpoint().to_string()
    }

    pub fn ws_url(&self) -> String {
        self._anvil.ws_endpoint().to_string()
    }

    pub async fn create_account(&self, auth_addr: Address, pubkey: U256, commitment: u64) {
        let deployer = self._anvil.signer(0).unwrap();
        let registry = WorldIDRegistry::new(
            self.registry_address,
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(deployer))
                .connect_http(self._anvil.endpoint().parse().unwrap()),
        );
        registry
            .createAccount(
                RECOVERY_ADDRESS,
                vec![auth_addr],
                vec![pubkey],
                U256::from(commitment),
            )
            .send()
            .await
            .expect("failed to submit createAccount transaction")
            .get_receipt()
            .await
            .expect("createAccount transaction failed");
    }

    pub async fn get_root(&self) -> U256 {
        let deployer = self._anvil.signer(0).unwrap();
        let registry = WorldIDRegistry::new(
            self.registry_address,
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(deployer))
                .connect_http(self._anvil.endpoint().parse().unwrap()),
        );
        registry.currentRoot().call().await.unwrap()
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

    pub async fn wait_for_health(host_url: &str) {
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

pub async fn query_count(pool: &PgPool) -> i64 {
    let rec: (i64,) = sqlx::query_as("select count(*) from accounts")
        .fetch_one(pool)
        .await
        .unwrap();
    rec.0
}
