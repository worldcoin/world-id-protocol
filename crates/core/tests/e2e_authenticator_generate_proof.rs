#![cfg(feature = "authenticator")]

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::U256;
use eyre::{eyre, Context as _, Result};
use taceo_oprf_types::ShareEpoch;
use test_utils::{
    fixtures::{
        build_base_credential, generate_rp_fixture, single_leaf_merkle_fixture, MerkleFixture,
        RegistryTestContext,
    },
    stubs::spawn_indexer_stub,
};
use world_id_core::{
    requests::{ProofRequest, RequestItem, RequestVersion},
    Authenticator, AuthenticatorError, HashableCredential,
};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig, SignerArgs};
use world_id_primitives::{
    merkle::AccountInclusionProof, rp::RpId, Config, FieldElement, TREE_DEPTH,
};

const GW_PORT: u16 = 4104;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let RegistryTestContext {
        anvil,
        world_id_registry: registry_address,
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

    // deploy the OprfKeyRegistry
    let oprf_registry = anvil.deploy_oprf_key_registry(deployer.clone()).await?;
    // signers must match the ones used in the TestSecretManager
    let oprf_node_signers = [anvil.signer(5)?, anvil.signer(6)?, anvil.signer(7)?];
    anvil
        .register_oprf_nodes(
            oprf_registry,
            deployer.clone(),
            oprf_node_signers.iter().map(|s| s.address()).collect(),
        )
        .await?;

    // Spawn the gateway wired to this Anvil instance.
    let signer_args = SignerArgs::from_wallet(hex::encode(deployer.to_bytes()));
    let gateway_config = GatewayConfig {
        registry_addr: registry_address,
        rpc_url: anvil.endpoint().to_string(),
        signer_args,
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: None,
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
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        registry_address,
        "http://127.0.0.1:0".to_string(), // placeholder for future indexer stub
        format!("http://127.0.0.1:{GW_PORT}"),
        Vec::new(),
        2,
    )
    .unwrap();

    // World ID should not yet exist.
    let init_result = Authenticator::init(&seed, creation_config.clone()).await;
    assert!(
        matches!(init_result, Err(AuthenticatorError::AccountDoesNotExist)),
        "expected missing account error before creation"
    );

    // Create the account via the gateway, blocking until confirmed.
    let start = SystemTime::now();
    let authenticator =
        Authenticator::init_or_register(&seed, creation_config.clone(), Some(recovery_address))
            .await
            .unwrap();
    println!(
        "Authentication creation took: {}ms",
        SystemTime::now().duration_since(start).unwrap().as_millis(),
    );

    assert_eq!(authenticator.leaf_index(), U256::from(1u64));
    assert_eq!(authenticator.recovery_counter(), U256::ZERO);

    // Re-initialize to ensure account metadata is persisted.
    let authenticator = Authenticator::init(&seed, creation_config)
        .await
        .wrap_err("expected authenticator to initialize after account creation")?;
    assert_eq!(authenticator.leaf_index(), U256::from(1u64));

    // Local indexer stub serving inclusion proof.
    let leaf_index_u64: u64 = authenticator
        .leaf_index()
        .try_into()
        .expect("account id fits in u64");
    let MerkleFixture {
        key_set,
        inclusion_proof: merkle_inclusion_proof,
        root: _,
        ..
    } = single_leaf_merkle_fixture(vec![authenticator.offchain_pubkey()], leaf_index_u64)
        .wrap_err("failed to construct merkle fixture")?;

    let inclusion_proof =
        AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_inclusion_proof, key_set.clone())
            .wrap_err("failed to build inclusion proof")?;

    let (indexer_url, indexer_handle) = spawn_indexer_stub(leaf_index_u64, inclusion_proof.clone())
        .await
        .wrap_err("failed to start indexer stub")?;

    let rp_fixture = generate_rp_fixture();

    let secret_managers = test_utils::taceo_oprf_test::create_3_secret_managers();
    // OPRF key-gen instances
    let oprf_key_gens = test_utils::stubs::spawn_key_gens(
        anvil.ws_endpoint(),
        secret_managers.clone(),
        oprf_registry,
    )
    .await;
    // OPRF nodes
    let nodes = test_utils::stubs::spawn_oprf_nodes(
        anvil.ws_endpoint(),
        secret_managers.clone(),
        oprf_registry,
        registry_address,
    )
    .await;

    test_utils::taceo_oprf_test::health_checks::services_health_check(
        &oprf_key_gens,
        Duration::from_secs(60),
    )
    .await?;

    // init key gen for a new RP, wait until its done and fetch the public key
    let oprf_key_id = anvil.init_oprf_key_gen(oprf_registry, deployer).await?;
    let oprf_public_key =
        test_utils::taceo_oprf_test::health_checks::oprf_public_key_from_services(
            oprf_key_id,
            ShareEpoch::default(),
            &nodes,
            Duration::from_secs(60),
        )
        .await?;

    // Config for proof generation uses the indexer + OPRF stubs.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_current_dir(&workspace_root)
        .wrap_err("failed to set working directory to workspace root")?;

    let proof_config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        registry_address,
        indexer_url.clone(),
        format!("http://127.0.0.1:{GW_PORT}"),
        nodes.to_vec(),
        2,
    )
    .unwrap();

    let authenticator = Authenticator::init(&seed, proof_config)
        .await
        .wrap_err("failed to reinitialize authenticator with proof config")?;
    assert_eq!(authenticator.leaf_index(), U256::from(1u64));

    // Create and sign credential.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let (mut credential, credential_sub_blinding_factor) =
        build_base_credential(issuer_schema_id_u64, leaf_index_u64, now, now + 60);
    credential.issuer = issuer_pk;
    let credential_hash = credential
        .hash()
        .wrap_err("failed to hash credential prior to signing")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    // Create a ProofRequest
    let proof_request = ProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        created_at: rp_fixture.current_timestamp,
        expires_at: rp_fixture.current_timestamp + 300, // 5 minutes from now
        rp_id: RpId::from(oprf_key_id.into_inner()),
        action: rp_fixture.action.into(),
        oprf_public_key,
        signature: rp_fixture.signature,
        nonce: rp_fixture.nonce.into(),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id: issuer_schema_id_u64.into(),
            signal: Some("my_signal".to_string()),
            genesis_issued_at_min: None,
            session_id: None,
        }],
        constraints: None,
    };

    // Call generate_proof and ensure a nullifier is produced.
    let (_proof, nullifier) = authenticator
        .generate_proof(proof_request, credential, credential_sub_blinding_factor)
        .await
        .wrap_err("failed to generate proof")?;
    assert_ne!(nullifier, FieldElement::ZERO);

    // FIXME: verify proof with verifier contract

    indexer_handle.abort();
    Ok(())
}
