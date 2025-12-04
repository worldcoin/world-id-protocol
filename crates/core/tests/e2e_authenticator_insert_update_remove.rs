#![cfg(feature = "authenticator")]

use std::time::Duration;

use alloy::primitives::{Address, U256};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use eyre::{Context as _, Result};
use reqwest::Client;
use test_utils::{
    anvil::TestAnvil,
    fixtures::{single_leaf_merkle_fixture, MerkleFixture},
    stubs::spawn_indexer_stub,
};
use tokio::task::JoinHandle;
use world_id_core::types::{GatewayRequestState, GatewayStatusResponse};
use world_id_core::{Authenticator, AuthenticatorError};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig};
use world_id_primitives::{merkle::AccountInclusionProof, Config, TREE_DEPTH};

const GW_PORT: u16 = 4105;

/// Test context holding common configuration for operations.
struct TestContext {
    rpc_url: String,
    chain_id: u64,
    registry_address: Address,
    gateway_url: String,
    http_client: Client,
}

impl TestContext {
    /// Creates a Config with the given indexer URL.
    fn config_with_indexer(&self, indexer_url: &str) -> Result<Config> {
        Config::new(
            Some(self.rpc_url.clone()),
            self.chain_id,
            self.registry_address,
            indexer_url.to_string(),
            self.gateway_url.clone(),
            Vec::new(),
            2,
        )
        .wrap_err("failed to create config")
    }

    /// Creates a Config with a placeholder indexer URL (for account creation via RPC).
    fn config_for_creation(&self) -> Result<Config> {
        self.config_with_indexer("http://127.0.0.1:0")
    }

    /// Waits for a gateway request to finalize, returning the tx hash.
    async fn wait_for_finalized(&self, request_id: &str) -> Result<String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let resp = self
                .http_client
                .get(format!("{}/status/{}", self.gateway_url, request_id))
                .send()
                .await?;

            let status_code = resp.status();
            if status_code == reqwest::StatusCode::NOT_FOUND {
                eyre::bail!("request {request_id} not found");
            }
            if !status_code.is_success() {
                let body_text = resp.text().await.unwrap_or_default();
                eyre::bail!(
                    "status check for {request_id} failed: {} body={}",
                    status_code,
                    body_text
                );
            }

            let body: GatewayStatusResponse = resp.json().await?;
            match body.status {
                GatewayRequestState::Finalized { tx_hash } => return Ok(tx_hash),
                GatewayRequestState::Failed { error } => {
                    eyre::bail!("request {request_id} failed: {error}");
                }
                _ => {
                    if std::time::Instant::now() > deadline {
                        eyre::bail!("timeout waiting for request {request_id} to finalize");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Sets up an indexer stub with a Merkle proof for the given pubkeys.
/// Returns the indexer URL and a handle to abort the stub.
async fn setup_indexer_stub(
    pubkeys: Vec<EdDSAPublicKey>,
    leaf_index: u64,
) -> Result<(String, JoinHandle<()>)> {
    let MerkleFixture {
        key_set,
        inclusion_proof,
        ..
    } = single_leaf_merkle_fixture(pubkeys, leaf_index)
        .wrap_err("failed to create merkle fixture")?;

    let account_proof =
        AccountInclusionProof::<{ TREE_DEPTH }>::new(inclusion_proof, key_set)
            .wrap_err("failed to create account inclusion proof")?;

    spawn_indexer_stub(leaf_index, account_proof)
        .await
        .wrap_err("failed to spawn indexer stub")
}

/// Derives offchain pubkey and onchain address from a seed (same logic as internal Signer).
fn derive_keys_from_seed(seed: [u8; 32]) -> (EdDSAPublicKey, Address) {
    use alloy::signers::local::PrivateKeySigner;
    let onchain_signer = PrivateKeySigner::from_bytes(&seed.into()).expect("valid key");
    let offchain_sk = EdDSAPrivateKey::from_bytes(seed);
    (offchain_sk.public(), onchain_signer.address())
}

/// E2E test for authenticator insert, update, and remove operations.
///
/// This test verifies that the on-chain signature nonce is correctly incremented
/// after each authenticator operation.
///
/// Flow:
/// 1. Creates an account via the gateway (nonce starts at 0)
/// 2. Inserts a second authenticator at index 1 (nonce becomes 1)
/// 3. Updates the original authenticator at index 0 (nonce becomes 2)
/// 4. Removes the updated authenticator at index 0 using the inserted authenticator (nonce becomes 3)
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_insert_update_remove() -> Result<()> {
    // --- Setup: Anvil (forked for Multicall3), Registry, Gateway ---
    let anvil = TestAnvil::spawn_fork("https://reth-ethereum.ithaca.xyz/rpc")
        .wrap_err("failed to spawn forked anvil")?;
    let deployer = anvil.signer(0).wrap_err("failed to fetch deployer signer")?;

    let registry_address = anvil
        .deploy_account_registry(deployer.clone())
        .await
        .wrap_err("failed to deploy account registry")?;

    let gateway_config = GatewayConfig {
        registry_addr: registry_address,
        rpc_url: anvil.endpoint().to_string(),
        wallet_private_key: Some(hex::encode(deployer.to_bytes())),
        aws_kms_key_id: None,
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
    };

    let _gateway = spawn_gateway_for_tests(gateway_config)
        .await
        .expect("failed to spawn gateway");

    let ctx = TestContext {
        rpc_url: anvil.endpoint().to_string(),
        chain_id: anvil.instance.chain_id(),
        registry_address,
        gateway_url: format!("http://127.0.0.1:{GW_PORT}"),
        http_client: Client::new(),
    };

    // --- Create Account with Primary Authenticator ---
    let primary_seed = [42u8; 32];
    let recovery_address = anvil
        .signer(1)
        .wrap_err("failed to fetch recovery signer")?
        .address();

    // Verify account doesn't exist yet
    let result = Authenticator::init(&primary_seed, ctx.config_for_creation()?).await;
    assert!(
        matches!(result, Err(AuthenticatorError::AccountDoesNotExist)),
        "expected AccountDoesNotExist error before creation"
    );

    // Create the account
    let primary_authenticator = Authenticator::init_or_create_blocking(
        &primary_seed,
        ctx.config_for_creation()?,
        Some(recovery_address),
    )
    .await
    .wrap_err("failed to create account")?;

    assert_eq!(primary_authenticator.leaf_index(), U256::from(1));
    assert_eq!(primary_authenticator.recovery_counter(), U256::from(0));
    assert_eq!(
        primary_authenticator.signing_nonce().await?,
        U256::from(0),
        "initial nonce should be 0"
    );

    let leaf_index_u64: u64 = primary_authenticator
        .leaf_index()
        .try_into()
        .wrap_err("leaf index too large")?;

    // --- Prepare Secondary Authenticator (will be inserted) ---
    let secondary_seed = [43u8; 32];
    let (secondary_offchain_pubkey, secondary_onchain_address) =
        derive_keys_from_seed(secondary_seed);

    // ==========================================================
    // INSERT: Add secondary authenticator to the account
    // ==========================================================
    let (indexer_url, indexer_handle) = setup_indexer_stub(
        vec![primary_authenticator.offchain_pubkey()],
        leaf_index_u64,
    )
    .await?;

    let mut primary_ops = Authenticator::init(&primary_seed, ctx.config_with_indexer(&indexer_url)?)
        .await
        .wrap_err("failed to init authenticator for insert")?;

    assert_eq!(
        primary_ops.signing_nonce().await?,
        U256::from(0),
        "nonce should be 0 before insert"
    );

    let insert_request_id = primary_ops
        .insert_authenticator(secondary_offchain_pubkey.clone(), secondary_onchain_address)
        .await
        .wrap_err("failed to insert authenticator")?;

    println!("Insert request ID: {insert_request_id}");
    let insert_tx = ctx.wait_for_finalized(&insert_request_id).await?;
    println!("Insert finalized in tx: {insert_tx}");

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        primary_ops.signing_nonce().await?,
        U256::from(1),
        "nonce should be 1 after insert"
    );

    indexer_handle.abort();

    // ==========================================================
    // UPDATE: Replace the primary authenticator (index 0)
    // ==========================================================
    let (indexer_url, indexer_handle) = setup_indexer_stub(
        vec![
            primary_authenticator.offchain_pubkey(),
            secondary_offchain_pubkey.clone(),
        ],
        leaf_index_u64,
    )
    .await?;

    let mut primary_ops = Authenticator::init(&primary_seed, ctx.config_with_indexer(&indexer_url)?)
        .await
        .wrap_err("failed to init authenticator for update")?;

    // Generate new keys for the updated authenticator
    let mut rng = rand::thread_rng();
    let updated_pubkey = EdDSAPrivateKey::random(&mut rng).public();
    let updated_onchain_address = anvil
        .signer(3)
        .wrap_err("failed to fetch signer 3")?
        .address();
    let primary_onchain_address = primary_ops.onchain_address();

    assert_eq!(
        primary_ops.signing_nonce().await?,
        U256::from(1),
        "nonce should be 1 before update"
    );

    let update_request_id = primary_ops
        .update_authenticator(
            primary_onchain_address,
            updated_onchain_address,
            updated_pubkey.clone(),
            0, // index of primary authenticator
        )
        .await
        .wrap_err("failed to update authenticator")?;

    println!("Update request ID: {update_request_id}");
    let update_tx = ctx.wait_for_finalized(&update_request_id).await?;
    println!("Update finalized in tx: {update_tx}");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Query nonce directly since primary authenticator is now invalid
    let nonce_after_update = {
        use alloy::providers::ProviderBuilder;
        use test_utils::anvil::AccountRegistry;
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
        AccountRegistry::new(registry_address, provider)
            .leafIndexToSignatureNonce(U256::from(1))
            .call()
            .await?
    };
    assert_eq!(nonce_after_update, U256::from(2), "nonce should be 2 after update");

    indexer_handle.abort();

    // ==========================================================
    // REMOVE: Remove the updated authenticator using secondary
    // ==========================================================
    let (indexer_url, indexer_handle) = setup_indexer_stub(
        vec![updated_pubkey.clone(), secondary_offchain_pubkey.clone()],
        leaf_index_u64,
    )
    .await?;

    // Use secondary authenticator (still valid at index 1) to sign the remove
    let mut secondary_ops =
        Authenticator::init(&secondary_seed, ctx.config_with_indexer(&indexer_url)?)
            .await
            .wrap_err("failed to init secondary authenticator for remove")?;

    assert_eq!(
        secondary_ops.signing_nonce().await?,
        U256::from(2),
        "nonce should be 2 before remove"
    );

    let remove_request_id = secondary_ops
        .remove_authenticator(updated_onchain_address, 0)
        .await
        .wrap_err("failed to remove authenticator")?;

    println!("Remove request ID: {remove_request_id}");
    let remove_tx = ctx.wait_for_finalized(&remove_request_id).await?;
    println!("Remove finalized in tx: {remove_tx}");

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        secondary_ops.signing_nonce().await?,
        U256::from(3),
        "nonce should be 3 after remove"
    );

    indexer_handle.abort();

    println!("All authenticator operations completed successfully!");
    println!("Nonce progression: 0 -> 1 (insert) -> 2 (update) -> 3 (remove)");

    Ok(())
}
