#![cfg(feature = "authenticator")]

use std::sync::Arc;

use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use world_id_core::{
    Authenticator, AuthenticatorError,
    artifacts::{ZkArtifactSource, dummy::DummyZkArtifactSource},
    world_id_registry::{WorldIdRegistry, domain, sign_recover_account},
};
use world_id_primitives::{Config, ServiceEndpoint};
use world_id_test_utils::anvil::TestAnvil;

fn dummy_zk_source() -> Arc<dyn ZkArtifactSource> {
    Arc::new(DummyZkArtifactSource)
}

// After an on-chain recovery, the registry still returns the old authenticator's packed
// account data, so `Authenticator::init` over direct RPC must reject it via the recovery
// counter instead of initializing against the recovered account's leaf index.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn init_fails_for_authenticator_revoked_by_recovery() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");

    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    let deployer = anvil.signer(0).unwrap();
    let recovery_agent = anvil.signer(1).unwrap();
    let registry_address = anvil
        .deploy_world_id_registry(deployer.clone())
        .await
        .unwrap();

    let provider = ProviderBuilder::new()
        .wallet(deployer)
        .connect_http(anvil.endpoint().parse().unwrap());
    let chain_id = provider.get_chain_id().await.unwrap();
    let registry = WorldIdRegistry::new(registry_address, provider);

    // Register an account whose only authenticator is the address derived from `seed`.
    let seed = [7u8; 32];
    let auth_addr = PrivateKeySigner::from_bytes(&seed.into())
        .unwrap()
        .address();
    let old_commitment = U256::from(2);
    registry
        .createAccount(
            recovery_agent.address(),
            vec![auth_addr],
            vec![U256::from(1)],
            old_commitment,
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let config = Config::new(
        Some(anvil.endpoint().to_string()),
        chain_id,
        registry_address,
        ServiceEndpoint::direct("http://127.0.0.1:0".to_string()),
        ServiceEndpoint::direct("http://127.0.0.1:0".to_string()),
        Vec::new(),
        2,
    )
    .unwrap();

    let auth = Authenticator::init(&seed, config.clone(), dummy_zk_source())
        .await
        .unwrap();
    let leaf_index = auth.leaf_index();

    // Recover the account to a fresh authenticator, revoking the original one.
    let new_auth_addr = anvil.signer(2).unwrap().address();
    let new_commitment = U256::from(3);
    let nonce = registry.getSignatureNonce(leaf_index).call().await.unwrap();
    let signature = sign_recover_account(
        &recovery_agent,
        leaf_index,
        new_auth_addr,
        U256::from(4),
        new_commitment,
        nonce,
        &domain(chain_id, registry_address),
    )
    .await
    .unwrap();
    registry
        .recoverAccount(
            leaf_index,
            new_auth_addr,
            U256::from(4),
            old_commitment,
            new_commitment,
            signature.as_bytes().to_vec().into(),
            nonce,
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let result = Authenticator::init(&seed, config, dummy_zk_source()).await;
    assert!(matches!(
        result,
        Err(AuthenticatorError::AccountDoesNotExist)
    ));
}
