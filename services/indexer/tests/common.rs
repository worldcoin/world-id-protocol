#![allow(dead_code)]

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, address},
    providers::ProviderBuilder,
};
use regex::Regex;
use sqlx::{Executor, PgPool, postgres::PgPoolOptions};
use test_utils::anvil::TestAnvil;
use tracing::info;
use uuid::Uuid;
use world_id_core::world_id_registry::WorldIdRegistry;
use world_id_indexer::db::DB;
use world_id_primitives::TREE_DEPTH;

pub const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");

pub struct TestSetup {
    pub _anvil: TestAnvil,
    pub registry_address: Address,
    pub db_url: String,
    pub pool: PgPool,
    db_name: String,
}

impl TestSetup {
    pub async fn new() -> Self {
        Self::new_with_tree_depth(TREE_DEPTH as u64).await
    }

    pub async fn new_with_tree_depth(tree_depth: u64) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let (db_url, db_name) = Self::setup_test_database().await;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("failed to connect to test database");

        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let deployer = anvil.signer(0).expect("failed to obtain deployer signer");
        let registry_address = anvil
            .deploy_world_id_registry_with_depth(deployer, tree_depth)
            .await
            .expect("failed to deploy WorldIDRegistry");

        Self {
            _anvil: anvil,
            registry_address,
            db_url,
            pool,
            db_name,
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
        let registry = WorldIdRegistry::new(
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
        let registry = WorldIdRegistry::new(
            self.registry_address,
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(deployer))
                .connect_http(self._anvil.endpoint().parse().unwrap()),
        );
        registry.currentRoot().call().await.unwrap()
    }

    async fn setup_test_database() -> (String, String) {
        let base_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://postgres:postgres@localhost:5432/postgres".to_string()
        });

        // Generate unique database name
        let unique_name = format!("indexer_tests_{}", Uuid::new_v4().simple());

        {
            let re = Regex::new(r"/[^/]+(\??)$").unwrap();
            let base_url = re.replace_all(&base_url, "/postgres${1}");

            let db = DB::new(&base_url, Some(1)).await.unwrap();

            info!("Creating database {}...", unique_name);
            db.pool()
                .execute(format!("CREATE DATABASE {}", unique_name).as_str())
                .await
                .unwrap();
            info!("Database created.");
        }

        // Properly replace just the database name in the URL
        let db_url = if let Some(pos) = base_url.rfind('/') {
            format!("{}/{}", &base_url[..pos], unique_name)
        } else {
            format!("{}/{}", base_url, unique_name)
        };
        let db = DB::new(&db_url, Some(1)).await.unwrap();
        db.run_migrations().await.unwrap();

        (db_url, unique_name)
    }

    async fn cleanup_test_database(db_name: &str) {
        let base_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://postgres:postgres@localhost:5432/postgres".to_string()
        });

        let re = Regex::new(r"/[^/]+(\??)$").unwrap();
        let base_url = re.replace_all(&base_url, "/postgres${1}");

        if let Ok(pool) = PgPoolOptions::new()
            .max_connections(1)
            .connect(base_url.as_ref())
            .await
        {
            info!("Terminating connections to database {}...", db_name);
            // Terminate all active connections to the database first
            let _ = sqlx::query(&format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                db_name
            ))
            .execute(&pool)
            .await;

            info!("Dropping database {}...", db_name);
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
                .execute(&pool)
                .await;
            info!("Database {} dropped.", db_name);
        }
    }

    pub async fn wait_for_health(host_url: &str) {
        let client = reqwest::Client::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);

        loop {
            if let Ok(resp) = client.get(format!("{host_url}/health")).send().await
                && resp.status().is_success()
            {
                return;
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
        // Close the pool to release connections
        // Note: pool.close() is not async, it just marks the pool for closure.
        // The cleanup_test_database function uses pg_terminate_backend to force-close
        // any remaining connections before dropping the database.
        self.pool.close();

        let db_name = self.db_name.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                rt.block_on(async {
                    Self::cleanup_test_database(&db_name).await;
                });
            }
        })
        .join();
    }
}

pub async fn query_count(pool: &PgPool) -> i64 {
    let rec: (i64,) = sqlx::query_as("select count(*) from accounts")
        .fetch_one(pool)
        .await
        .unwrap();
    rec.0
}
