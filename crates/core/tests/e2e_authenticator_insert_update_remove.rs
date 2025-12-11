#![cfg(feature = "authenticator")]

use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use reqwest::Client;
use test_utils::{
    anvil::{TestAnvil, WorldIDRegistry},
    fixtures::{single_leaf_merkle_fixture, MerkleFixture},
    stubs::MutableIndexerStub,
};
use world_id_core::types::{GatewayRequestState, GatewayStatusResponse};
use world_id_core::{Authenticator, AuthenticatorError};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig};
use world_id_primitives::{merkle::AccountInclusionProof, Config, TREE_DEPTH};

const GW_PORT: u16 = 4105;

async fn wait_for_finalized(client: &Client, base: &str, request_id: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let resp = client
            .get(format!("{base}/status/{request_id}"))
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            panic!("request {request_id} not found");
        }
        if !resp.status().is_success() {
            panic!("status check failed: {}", resp.status());
        }
        let body: GatewayStatusResponse = resp.json().await.unwrap();
        match body.status {
            GatewayRequestState::Finalized { .. } => return,
            GatewayRequestState::Failed { error, .. } => panic!("request failed: {error}"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!("timeout waiting for request to finalize");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// Creates a merkle inclusion proof for the given pubkeys
fn make_inclusion_proof(
    pubkeys: Vec<EdDSAPublicKey>,
    leaf_index: u64,
) -> AccountInclusionProof<{ TREE_DEPTH }> {
    let MerkleFixture {
        key_set,
        inclusion_proof,
        ..
    } = single_leaf_merkle_fixture(pubkeys, leaf_index).unwrap();
    AccountInclusionProof::<{ TREE_DEPTH }>::new(inclusion_proof, key_set).unwrap()
}

// Derives keys from seed using same logic as Authenticator's internal Signer
fn derive_keys_from_seed(seed: [u8; 32]) -> (EdDSAPublicKey, Address) {
    let onchain = PrivateKeySigner::from_bytes(&seed.into()).unwrap();
    let offchain = EdDSAPrivateKey::from_bytes(seed);
    (offchain.public(), onchain.address())
}

fn make_config(
    rpc_url: &str,
    chain_id: u64,
    registry: Address,
    indexer_url: &str,
    gateway_url: &str,
) -> Config {
    Config::new(
        Some(rpc_url.to_string()),
        chain_id,
        registry,
        indexer_url.to_string(),
        gateway_url.to_string(),
        Vec::new(),
        2,
    )
    .unwrap()
}

// Tests that the on-chain nonce increments correctly after each authenticator operation.
// Flow: create account (nonce=0) -> insert (nonce=1) -> update (nonce=2) -> remove (nonce=3)
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_insert_update_remove() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let anvil = TestAnvil::spawn_with_multicall3()
        .await
        .expect("failed to spawn anvil with multicall3");
    let deployer = anvil.signer(0).unwrap();
    let registry_address = anvil
        .deploy_world_id_registry(deployer.clone())
        .await
        .unwrap();

    let gateway_config = GatewayConfig {
        registry_addr: registry_address,
        rpc_url: anvil.endpoint().to_string(),
        wallet_private_key: Some(hex::encode(deployer.to_bytes())),
        aws_kms_key_id: None,
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: None,
    };
    let _gateway = spawn_gateway_for_tests(gateway_config)
        .await
        .expect("failed to spawn gateway");

    let rpc_url = anvil.endpoint().to_string();
    let chain_id = anvil.instance.chain_id();
    let gateway_url = format!("http://127.0.0.1:{GW_PORT}");
    let client = Client::new();

    // Create account with primary authenticator (index 0)
    let primary_seed = [42u8; 32];
    let recovery_address = anvil.signer(1).unwrap().address();

    let config = make_config(
        &rpc_url,
        chain_id,
        registry_address,
        "http://127.0.0.1:0",
        &gateway_url,
    );
    let result = Authenticator::init(&primary_seed, config.clone()).await;
    assert!(matches!(
        result,
        Err(AuthenticatorError::AccountDoesNotExist)
    ));

    let primary =
        Authenticator::init_or_create_blocking(&primary_seed, config, Some(recovery_address))
            .await
            .unwrap();
    assert_eq!(primary.leaf_index(), U256::from(1));
    assert_eq!(primary.signing_nonce().await.unwrap(), U256::from(0));

    let leaf_index: u64 = primary.leaf_index().try_into().unwrap();

    // Prepare secondary authenticator keys (will be inserted at index 1)
    let secondary_seed = [43u8; 32];
    let (secondary_pubkey, secondary_address) = derive_keys_from_seed(secondary_seed);

    // Spawn a single indexer stub that we'll update throughout the test
    let initial_proof = make_inclusion_proof(vec![primary.offchain_pubkey()], leaf_index);
    let indexer = MutableIndexerStub::spawn(leaf_index, initial_proof)
        .await
        .unwrap();

    // INSERT: add secondary authenticator, signed by primary
    // Key set before: [primary]. Key set after: [primary, secondary]
    let config = make_config(
        &rpc_url,
        chain_id,
        registry_address,
        &indexer.url,
        &gateway_url,
    );
    let mut auth = Authenticator::init(&primary_seed, config).await.unwrap();

    assert_eq!(auth.signing_nonce().await.unwrap(), U256::from(0));
    let req_id = auth
        .insert_authenticator(secondary_pubkey.clone(), secondary_address)
        .await
        .unwrap();
    wait_for_finalized(&client, &gateway_url, &req_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(auth.signing_nonce().await.unwrap(), U256::from(1));

    // Verify secondary authenticator is now registered in the contract
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    let contract = WorldIDRegistry::new(registry_address, provider);
    let packed = contract
        .authenticatorAddressToPackedAccountData(secondary_address)
        .call()
        .await
        .unwrap();
    assert_ne!(
        packed,
        U256::from(0),
        "secondary authenticator should be registered after insert"
    );

    // UPDATE: replace primary authenticator (index 0) with new keys, signed by primary
    // Key set before: [primary, secondary]. Key set after: [updated, secondary]
    indexer.set_proof(make_inclusion_proof(
        vec![primary.offchain_pubkey(), secondary_pubkey.clone()],
        leaf_index,
    ));
    let config = make_config(
        &rpc_url,
        chain_id,
        registry_address,
        &indexer.url,
        &gateway_url,
    );
    let mut auth = Authenticator::init(&primary_seed, config).await.unwrap();

    let updated_pubkey = EdDSAPrivateKey::random(&mut rand::thread_rng()).public();
    let updated_address = anvil.signer(3).unwrap().address();
    let primary_address = auth.onchain_address();

    assert_eq!(auth.signing_nonce().await.unwrap(), U256::from(1));
    let req_id = auth
        .update_authenticator(primary_address, updated_address, updated_pubkey.clone(), 0)
        .await
        .unwrap();
    wait_for_finalized(&client, &gateway_url, &req_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Primary authenticator is now invalid, query contract directly
    let nonce = contract
        .leafIndexToSignatureNonce(U256::from(1))
        .call()
        .await
        .unwrap();
    assert_eq!(nonce, U256::from(2));

    // Verify updated authenticator is registered and old primary is cleared
    let packed = contract
        .authenticatorAddressToPackedAccountData(updated_address)
        .call()
        .await
        .unwrap();
    assert_ne!(
        packed,
        U256::from(0),
        "updated authenticator should be registered after update"
    );
    let packed = contract
        .authenticatorAddressToPackedAccountData(primary_address)
        .call()
        .await
        .unwrap();
    assert_eq!(
        packed,
        U256::from(0),
        "old primary authenticator should be cleared after update"
    );

    // REMOVE: remove updated authenticator (index 0), signed by secondary
    // Key set before: [updated, secondary]. Key set after: [_, secondary]
    indexer.set_proof(make_inclusion_proof(
        vec![updated_pubkey.clone(), secondary_pubkey.clone()],
        leaf_index,
    ));
    let config = make_config(
        &rpc_url,
        chain_id,
        registry_address,
        &indexer.url,
        &gateway_url,
    );
    let mut auth = Authenticator::init(&secondary_seed, config).await.unwrap();

    assert_eq!(auth.signing_nonce().await.unwrap(), U256::from(2));
    let req_id = auth.remove_authenticator(updated_address, 0).await.unwrap();
    wait_for_finalized(&client, &gateway_url, &req_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(auth.signing_nonce().await.unwrap(), U256::from(3));

    // Verify updated authenticator is cleared after removal
    let packed = contract
        .authenticatorAddressToPackedAccountData(updated_address)
        .call()
        .await
        .unwrap();
    assert_eq!(
        packed,
        U256::from(0),
        "updated authenticator should be cleared after remove"
    );

    // Verify secondary authenticator is still registered (it was the signer for removal)
    let packed = contract
        .authenticatorAddressToPackedAccountData(secondary_address)
        .call()
        .await
        .unwrap();
    assert_ne!(
        packed,
        U256::from(0),
        "secondary authenticator should still be registered"
    );

    indexer.abort();
}
