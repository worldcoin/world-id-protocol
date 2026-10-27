#![allow(dead_code)]

use std::time::Duration;

use super::db_helpers::{TestDatabase, create_unique_test_db};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use sqlx::PgPool;
use world_id_primitives::TREE_DEPTH;
use world_id_registries::world_id::{WorldIdRegistry, domain, sign_recover_account};
use world_id_test_utils::anvil::TestAnvil;

pub const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");

pub struct TestSetup {
    pub _anvil: TestAnvil,
    pub registry_address: Address,
    pub db_url: String,
    pub pool: PgPool,
    _test_db: TestDatabase, // Holds reference for automatic cleanup via RAII
}

impl TestSetup {
    pub async fn new() -> Self {
        Self::new_with_tree_depth(TREE_DEPTH as u64).await
    }

    pub async fn new_with_tree_depth(tree_depth: u64) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let test_db = create_unique_test_db().await;
        let db_url = test_db.db_url().to_string();
        let pool = test_db.db.pool().clone();

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
            _test_db: test_db,
        }
    }

    pub fn rpc_url(&self) -> String {
        self._anvil.endpoint().to_string()
    }

    pub fn ws_url(&self) -> String {
        self._anvil.ws_endpoint().to_string()
    }

    /// Provider that signs as the anvil deployer account.
    fn provider(&self) -> DynProvider {
        let deployer = self._anvil.signer(0).unwrap();
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer))
            .connect_http(self._anvil.endpoint().parse().unwrap())
            .erased()
    }

    pub async fn create_account(&self, auth_addr: Address, pubkey: U256, commitment: u64) {
        self.create_account_with_recovery_agent(auth_addr, pubkey, commitment, RECOVERY_ADDRESS)
            .await;
    }

    /// Like [`Self::create_account`], but the caller picks the recovery agent so the account can
    /// later be recovered with a signature via [`Self::recover_account`].
    pub async fn create_account_with_recovery_agent(
        &self,
        auth_addr: Address,
        pubkey: U256,
        commitment: u64,
        recovery_agent: Address,
    ) {
        let registry = WorldIdRegistry::new(self.registry_address, self.provider());
        registry
            .createAccount(
                recovery_agent,
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

    /// Recovers `leaf_index` onto `new_auth_addr`, bumping the on-chain recovery counter and
    /// revoking every authenticator the account had before.
    pub async fn recover_account(
        &self,
        leaf_index: u64,
        new_auth_addr: Address,
        new_pubkey: U256,
        old_commitment: U256,
        new_commitment: U256,
        recovery_agent: &PrivateKeySigner,
    ) {
        let provider = self.provider();
        let chain_id = provider.get_chain_id().await.unwrap();
        let registry = WorldIdRegistry::new(self.registry_address, provider);
        let nonce = registry.getSignatureNonce(leaf_index).call().await.unwrap();

        let signature = sign_recover_account(
            recovery_agent,
            leaf_index,
            new_auth_addr,
            new_pubkey,
            new_commitment,
            nonce,
            &domain(chain_id, self.registry_address),
        )
        .await
        .expect("failed to sign recoverAccount payload");

        registry
            .recoverAccount(
                leaf_index,
                new_auth_addr,
                new_pubkey,
                old_commitment,
                new_commitment,
                signature.as_bytes().to_vec().into(),
                nonce,
            )
            .send()
            .await
            .expect("failed to submit recoverAccount transaction")
            .get_receipt()
            .await
            .expect("recoverAccount transaction failed");
    }

    pub async fn get_root(&self) -> U256 {
        let registry = WorldIdRegistry::new(self.registry_address, self.provider());
        registry.currentRoot().call().await.unwrap()
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

pub async fn query_count(pool: &PgPool) -> i64 {
    let rec: (i64,) = sqlx::query_as("select count(*) from accounts")
        .fetch_one(pool)
        .await
        .unwrap();
    rec.0
}

/// Initialize tracing for tests that don't use TestSetup
/// This allows RUST_LOG to work in tests
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}
