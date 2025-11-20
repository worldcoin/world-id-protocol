#![cfg(feature = "authenticator")]

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::primitives::U256;
use eyre::{eyre, Context as _, Result};
use oprf_types::crypto::RpNullifierKey;
use oprf_world_types::MerkleRoot;
use test_utils::{
    fixtures::{
        build_base_credential, generate_rp_fixture, single_leaf_merkle_fixture, MerkleFixture,
        RegistryTestContext,
    },
    stubs::{spawn_indexer_stub, spawn_oprf_stub},
};
use world_id_core::{Authenticator, AuthenticatorError, HashableCredential};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig};
use world_id_primitives::{merkle::AccountInclusionProof, Config, FieldElement, TREE_DEPTH};

const GW_PORT: u16 = 4104;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    let RegistryTestContext {
        anvil,
        account_registry: registry_address,
        issuer_private_key: issuer_sk,
        issuer_public_key: issuer_pk,
        issuer_schema_id,
        ..
    } = RegistryTestContext::new().await?;

    let issuer_schema_id_u64 = issuer_schema_id
        .try_into()
        .expect("issuer schema id fits in u64");

    let deployer = anvil
        .signer(0)
        .wrap_err("failed to fetch deployer signer for anvil")?;

    // Spawn the gateway wired to this Anvil instance.
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
        .map_err(|e| eyre!("failed to spawn gateway for tests: {e}"))?;

    // Build Config and ensure Authenticator account creation works.
    let seed = [7u8; 32];
    let recovery_address = anvil
        .signer(1)
        .wrap_err("failed to fetch recovery signer")?
        .address();

    let creation_config = Config::new(
        anvil.endpoint().to_string(),
        registry_address,
        "http://127.0.0.1:0".to_string(), // placeholder for future indexer stub
        format!("http://127.0.0.1:{GW_PORT}"),
        Vec::new(),
        2,
    );

    // Account should not yet exist.
    let init_result = Authenticator::init(&seed, creation_config.clone()).await;
    assert!(
        matches!(init_result, Err(AuthenticatorError::AccountDoesNotExist)),
        "expected missing account error before creation"
    );

    // Create the account via the gateway, blocking until confirmed.
    let authenticator = Authenticator::init_or_create_blocking(
        &seed,
        creation_config.clone(),
        Some(recovery_address),
    )
    .await
    .wrap_err("failed to initialize or create authenticator")?;

    assert_eq!(authenticator.account_id(), U256::from(1u64));
    assert_eq!(authenticator.recovery_counter(), U256::ZERO);

    // Re-initialize to ensure account metadata is persisted.
    let authenticator = Authenticator::init(&seed, creation_config)
        .await
        .wrap_err("expected authenticator to initialize after account creation")?;
    assert_eq!(authenticator.account_id(), U256::from(1u64));

    // Local indexer stub serving inclusion proof.
    let account_id_u64: u64 = authenticator
        .account_id()
        .try_into()
        .expect("account id fits in u64");
    let MerkleFixture {
        key_set,
        inclusion_proof: merkle_inclusion_proof,
        root,
        ..
    } = single_leaf_merkle_fixture(vec![authenticator.offchain_pubkey()], account_id_u64)
        .wrap_err("failed to construct merkle fixture")?;

    let inclusion_proof =
        AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_inclusion_proof, key_set.clone())
            .wrap_err("failed to build inclusion proof")?;

    let (indexer_url, indexer_handle) = spawn_indexer_stub(account_id_u64, inclusion_proof.clone())
        .await
        .wrap_err("failed to start indexer stub")?;

    let rp_fixture = generate_rp_fixture();

    // Local OPRF peer stub setup.
    let merkle_root = MerkleRoot::from(*root);
    let rp_verifying_key = rp_fixture.signing_key.verifying_key().clone();
    let oprf_server = spawn_oprf_stub(
        merkle_root,
        rp_verifying_key,
        rp_fixture.oprf_rp_id,
        rp_fixture.share_epoch,
        rp_fixture.rp_secret,
    )
    .await
    .wrap_err("failed to start OPRF stub")?;

    // Config for proof generation uses the indexer + OPRF stubs.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_current_dir(&workspace_root)
        .wrap_err("failed to set working directory to workspace root")?;

    let proof_config = Config::new(
        anvil.endpoint().to_string(),
        registry_address,
        indexer_url.clone(),
        format!("http://127.0.0.1:{GW_PORT}"),
        vec![oprf_server.base_url.clone()],
        2,
    );
    let authenticator = Authenticator::init(&seed, proof_config)
        .await
        .wrap_err("failed to reinitialize authenticator with proof config")?;
    assert_eq!(authenticator.account_id(), U256::from(1u64));

    // Create and sign credential.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let mut credential = build_base_credential(issuer_schema_id_u64, account_id_u64, now, now + 60);
    credential.issuer = issuer_pk;
    let credential_hash = credential
        .hash()
        .wrap_err("failed to hash credential prior to signing")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    let rp_request = world_id_core::types::RpRequest {
        rp_id: rp_fixture.oprf_rp_id.into_inner().to_string(),
        rp_nullifier_key: RpNullifierKey::new(rp_fixture.rp_nullifier_point),
        signature: rp_fixture.signature,
        current_time_stamp: rp_fixture.current_timestamp,
        action_id: rp_fixture.action.into(),
        nonce: rp_fixture.nonce.into(),
    };

    // Call generate_proof and ensure a nullifier is produced.
    let (_proof, nullifier) = authenticator
        .generate_proof(rp_fixture.signal_hash, rp_request, credential)
        .await
        .wrap_err("failed to generate proof")?;
    assert_ne!(nullifier, FieldElement::ZERO);

    indexer_handle.abort();
    oprf_server.join_handle.abort();
    Ok(())
}
