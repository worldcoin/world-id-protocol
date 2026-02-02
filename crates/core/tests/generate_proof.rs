#![cfg(feature = "authenticator")]

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{U160, U256},
    signers::local::LocalSigner,
};
use eyre::{Context as _, Result, eyre};
use taceo_oprf::types::{OprfKeyId, ShareEpoch};
use taceo_oprf_test_utils::health_checks;
use test_utils::{
    anvil::WorldIDVerifier,
    fixtures::{
        MerkleFixture, RegistryTestContext, build_base_credential, generate_rp_fixture,
        single_leaf_merkle_fixture,
    },
    stubs::spawn_indexer_stub,
};
use world_id_core::{
    Authenticator, AuthenticatorError,
    requests::{ProofRequest, RequestItem, RequestVersion},
};
use world_id_gateway::{GatewayConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_primitives::{Config, FieldElement, TREE_DEPTH, merkle::AccountInclusionProof};

const GW_PORT: u16 = 4104;

/// Generates an entire end-to-end Uniqueness Proof Generator
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let (_localstack_container, localstack_url) =
        taceo_oprf_test_utils::localstack_testcontainer().await?;

    let RegistryTestContext {
        anvil,
        world_id_registry,
        rp_registry,
        oprf_key_registry,
        world_id_verifier,
        credential_registry,
        issuer_private_key: issuer_sk,
        issuer_public_key: issuer_pk,
        issuer_schema_id,
        ..
    } = RegistryTestContext::new().await?;

    let deployer = anvil
        .signer(0)
        .wrap_err("failed to fetch deployer signer for anvil")?;

    // Spawn the gateway wired to this Anvil instance.
    let signer_args = SignerArgs::from_wallet(hex::encode(deployer.to_bytes()));
    let gateway_config = GatewayConfig {
        registry_addr: world_id_registry,
        provider: world_id_gateway::ProviderArgs {
            http: Some(vec![anvil.endpoint().parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
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
        world_id_registry,
        "http://127.0.0.1:0".to_string(), // placeholder for future indexer stub
        format!("http://127.0.0.1:{GW_PORT}"),
        Vec::new(),
        3,
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

    // OPRF key-gen instances
    let oprf_key_gens =
        test_utils::stubs::spawn_key_gens(anvil.ws_endpoint(), &localstack_url, oprf_key_registry)
            .await;

    // OPRF nodes
    let nodes = test_utils::stubs::spawn_oprf_nodes(
        anvil.ws_endpoint(),
        &localstack_url,
        oprf_key_registry,
        world_id_registry,
        rp_registry,
        credential_registry,
    )
    .await;

    health_checks::services_health_check(&nodes, Duration::from_secs(60)).await?;
    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60)).await?;

    // Register the RP which also triggers a OPRF key-gen.
    let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
    anvil
        .register_rp(
            rp_registry,
            deployer.clone(),
            rp_fixture.world_rp_id,
            rp_signer.address(),
            rp_signer.address(),
            "taceo.oprf".to_string(),
        )
        .await?;

    // Wait for OPRF key-gen and until the RP OPRF public key is available from the nodes.
    let _oprf_public_key = health_checks::oprf_public_key_from_services(
        rp_fixture.oprf_key_id,
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;
    // Wait for OPRF key-gen and until the issuer OPRF public key is available from the nodes.
    // This key-gen is started in `RegistryTestContext::new()`
    let _oprf_public_key = health_checks::oprf_public_key_from_services(
        OprfKeyId::new(U160::from(issuer_schema_id)),
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;

    // Config for proof generation uses the indexer + OPRF stubs.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_current_dir(&workspace_root)
        .wrap_err("failed to set working directory to workspace root")?;

    let proof_config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        world_id_registry,
        indexer_url.clone(),
        format!("http://127.0.0.1:{GW_PORT}"),
        nodes.to_vec(),
        3,
    )
    .unwrap();

    let authenticator = Authenticator::init(&seed, proof_config)
        .await
        .wrap_err("failed to reinitialize authenticator with proof config")?;
    assert_eq!(authenticator.leaf_index(), U256::from(1u64));

    let credential_sub_blinding_factor = authenticator
        .generate_credential_blinding_factor(
            issuer_schema_id,
            OprfKeyId::new(U160::from(issuer_schema_id)),
            ShareEpoch::default(),
        )
        .await?;

    // Create and sign credential.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let mut credential = build_base_credential(
        issuer_schema_id,
        leaf_index_u64,
        now,
        now + 60,
        credential_sub_blinding_factor,
    );
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
        expires_at: rp_fixture.expiration_timestamp,
        rp_id: rp_fixture.world_rp_id,
        oprf_key_id: rp_fixture.oprf_key_id,
        share_epoch: rp_fixture.share_epoch,
        session_id: None,
        action: Some(rp_fixture.action.into()),
        signature: rp_fixture.signature,
        nonce: rp_fixture.nonce.into(),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id,
            signal: Some("my_signal".to_string()),
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    };
    let request_item = proof_request
        .find_request_by_issuer_schema_id(issuer_schema_id)
        .unwrap();

    let nullifier = authenticator.generate_nullifier(&proof_request).await?;
    let raw_nullifier = FieldElement::from(nullifier.verifiable_oprf_output.output);
    assert_ne!(raw_nullifier, FieldElement::ZERO);

    // Generate session_id_r_seed for proof generation
    let mut rng = rand::thread_rng();
    let session_id_r_seed = FieldElement::random(&mut rng); // Normally the authenticator would provide this from cache or (in the future) OPRF Nodes

    // Normally here the authenticator would check the nullifier is UNIQUE.

    let response_item = authenticator.generate_single_proof(
        nullifier,
        request_item,
        &credential,
        credential_sub_blinding_factor,
        session_id_r_seed,
        proof_request.session_id,
        proof_request.created_at,
    )?;

    assert_eq!(response_item.nullifier.unwrap(), raw_nullifier);

    // verify proof with verifier contract
    let world_id_verifier: WorldIDVerifier::WorldIDVerifierInstance<alloy::providers::DynProvider> =
        WorldIDVerifier::new(world_id_verifier, anvil.provider()?);
    world_id_verifier
        .verify(
            response_item.nullifier.unwrap().into(),
            rp_fixture.action.into(),
            rp_fixture.world_rp_id.into_inner(),
            rp_fixture.nonce.into(),
            request_item.signal_hash().into(),
            response_item.expires_at_min,
            issuer_schema_id,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            response_item.proof.unwrap().as_ethereum_representation(),
        )
        .call()
        .await?;

    indexer_handle.abort();
    Ok(())
}
