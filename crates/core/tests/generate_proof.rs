#![cfg(feature = "authenticator")]

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{U160, U256},
    signers::{SignerSync as _, local::LocalSigner},
};
use eyre::{Context as _, Result, eyre};
use taceo_oprf::{
    dev_client::health_checks,
    types::{OprfKeyId, ShareEpoch},
};
use tracing::info;
use tracing_subscriber::EnvFilter;
use world_id_core::{
    Authenticator, AuthenticatorError, CredentialInput, EdDSAPrivateKey,
    artifacts::{ZkArtifactSource, ZkArtifactSourceExt as _},
    requests::{ProofRequest, ProofType, RequestItem, RequestVersion},
};

fn zk_artifact_source() -> Arc<dyn ZkArtifactSource> {
    Arc::new(world_id_core::artifacts::embedded::EmbeddedZkArtifacts.cached())
}
use world_id_gateway::{
    BatchPolicyConfig, GatewayConfig, RegistryVersion, SignerArgs, defaults,
    spawn_gateway_for_tests,
};
use world_id_primitives::{
    Config, FieldElement, ServiceEndpoint, SessionId, SessionRef, TREE_DEPTH,
    merkle::AccountInclusionProof,
};
use world_id_test_utils::{
    anvil::WorldIDVerifierV2,
    fixtures::{
        MerkleFixture, RegistryTestContext, build_base_credential, generate_rp_fixture,
        single_leaf_merkle_fixture,
    },
    stubs::spawn_indexer_stub,
};

fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// Generates an entire end-to-end Uniqueness Proof Generator
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    init_test_tracing();
    info!("starting e2e_authenticator_generate_proof");

    let mut rng = rand::thread_rng();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let RegistryTestContext {
        anvil,
        world_id_registry,
        rp_registry,
        billing_contract,
        oprf_key_registry,
        world_id_verifier,
        credential_registry,
    } = RegistryTestContext::new().await?;
    info!(
        ?world_id_registry,
        ?rp_registry,
        ?oprf_key_registry,
        ?credential_registry,
        "registry test context initialized"
    );

    let deployer = anvil
        .signer(0)
        .wrap_err("failed to fetch deployer signer for anvil")?;

    // Spawn the gateway wired to this Anvil instance.
    let signer_args = SignerArgs::from_wallet(hex::encode(deployer.to_bytes()));
    let gateway_config = GatewayConfig {
        registry_addr: world_id_registry,
        registry_version: RegistryVersion::V2,
        provider: world_id_gateway::ProviderArgs {
            http: Some(vec![anvil.endpoint().parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
        request_timeout_secs: 10,
        rate_limit_max_requests: None,
        rate_limit_window_secs: None,
        sweeper_interval_secs: defaults::SWEEPER_INTERVAL_SECS,
        stale_queued_threshold_secs: defaults::STALE_QUEUED_THRESHOLD_SECS,
        stale_submitted_threshold_secs: defaults::STALE_SUBMITTED_THRESHOLD_SECS,
        batch_policy: BatchPolicyConfig::default(),
    };
    let gateway = spawn_gateway_for_tests(gateway_config)
        .await
        .map_err(|e| eyre!("failed to spawn gateway for tests: {e}"))?;
    let gw_addr = gateway.listen_addr;
    let gateway_url = format!("http://{}:{}", gw_addr.ip(), gw_addr.port());
    info!(port = gw_addr.port(), "gateway started");

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
        ServiceEndpoint::direct("http://127.0.0.1:0".to_string()), // placeholder for future indexer stub
        ServiceEndpoint::direct(gateway_url.clone()),
        Vec::new(),
        3,
    )
    .unwrap();
    // World ID should not yet exist.
    let init_result =
        Authenticator::init(&seed, creation_config.clone(), zk_artifact_source()).await;
    assert!(
        matches!(init_result, Err(AuthenticatorError::AccountDoesNotExist)),
        "expected missing account error before creation"
    );

    // Create the account via the gateway, blocking until confirmed.
    let start = SystemTime::now();
    let authenticator = Authenticator::init_or_register(
        &seed,
        creation_config.clone(),
        Some(recovery_address),
        zk_artifact_source(),
    )
    .await
    .unwrap();
    info!(
        elapsed_ms = SystemTime::now().duration_since(start).unwrap().as_millis(),
        "authenticator account creation finished"
    );

    assert_eq!(authenticator.leaf_index(), 1);
    assert_eq!(authenticator.recovery_counter(), U256::ZERO);

    // Re-initialize to ensure account metadata is persisted.
    let authenticator = Authenticator::init(&seed, creation_config, zk_artifact_source())
        .await
        .wrap_err("expected authenticator to initialize after account creation")?;
    assert_eq!(authenticator.leaf_index(), 1);

    // Local indexer stub serving inclusion proof.
    let leaf_index = authenticator.leaf_index();
    let MerkleFixture {
        key_set,
        inclusion_proof: merkle_inclusion_proof,
        root: _,
        ..
    } = single_leaf_merkle_fixture(vec![authenticator.offchain_pubkey()], leaf_index)
        .wrap_err("failed to construct merkle fixture")?;

    let inclusion_proof =
        AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_inclusion_proof, key_set.clone());

    let (indexer_url, indexer_handle) = spawn_indexer_stub(leaf_index, inclusion_proof.clone())
        .await
        .wrap_err("failed to start indexer stub")?;

    let rp_fixture = generate_rp_fixture();

    let (_postgres, connection_string) = taceo_oprf_test_utils::postgres_testcontainer().await?;

    let node_secret_managers =
        world_id_test_utils::stubs::init_test_secret_managers(connection_string.clone().into())
            .await?;

    // OPRF key-gen instances
    let oprf_key_gens =
        world_id_test_utils::stubs::spawn_key_gens(&anvil, &connection_string, oprf_key_registry)
            .await?;

    // OPRF nodes
    let nodes = world_id_test_utils::stubs::spawn_oprf_nodes(
        &anvil,
        node_secret_managers,
        world_id_registry,
        rp_registry,
        billing_contract,
        credential_registry,
    )
    .await;

    health_checks::services_health_check(&nodes, Duration::from_secs(60)).await?;
    health_checks::services_health_check(&oprf_key_gens.urls, Duration::from_secs(60)).await?;
    info!("oprf nodes and key-gen services passed health checks");

    // Register an issuer which also triggers a OPRF key-gen.
    let issuer_schema_id = 1u64;
    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();
    anvil
        .register_issuer(
            credential_registry,
            deployer.clone(),
            issuer_schema_id,
            issuer_pk.clone(),
        )
        .await?;
    info!(issuer_schema_id, "issuer registered");

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
    info!(rp_id = ?rp_fixture.world_rp_id, "rp registered");

    // Wait for RP OPRF key-gen and until the public key is available from the nodes.
    let _oprf_public_key = health_checks::oprf_public_key_from_services(
        rp_fixture.oprf_key_id,
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;
    // Wait for issuer OPRF key-gen and until the public key is available from the nodes.
    // This key-gen is started in `RegistryTestContext::new()`
    let _oprf_public_key = health_checks::oprf_public_key_from_services(
        OprfKeyId::new(U160::from(issuer_schema_id)),
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;
    info!("oprf public keys became available for rp and issuer");

    // Config for proof generation uses the indexer + OPRF stubs.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_current_dir(&workspace_root)
        .wrap_err("failed to set working directory to workspace root")?;

    let proof_config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        world_id_registry,
        ServiceEndpoint::direct(indexer_url.clone()),
        ServiceEndpoint::direct(gateway_url.clone()),
        nodes.to_vec(),
        3,
    )
    .unwrap();

    let authenticator = Authenticator::init(&seed, proof_config, zk_artifact_source())
        .await
        .wrap_err("failed to reinitialize authenticator with proof config")?;
    assert_eq!(authenticator.leaf_index(), 1);

    let leaf_index = authenticator.leaf_index();
    let credential_sub_blinding_factor = authenticator
        .generate_credential_blinding_factor(issuer_schema_id)
        .await?;

    // Create and sign credential.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let mut credential = build_base_credential(
        issuer_schema_id,
        leaf_index,
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
        proof_type: ProofType::Uniqueness,
        created_at: rp_fixture.current_timestamp,
        expires_at: rp_fixture.expiration_timestamp,
        rp_id: rp_fixture.world_rp_id,
        oprf_key_id: rp_fixture.oprf_key_id,
        session_id: SessionRef::None,
        action: Some(rp_fixture.action.into()),
        signature: rp_fixture.signature,
        nonce: rp_fixture.nonce.into(),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id,
            signal: Some(b"my_signal".to_vec()),
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    };
    let nullifier = authenticator
        .generate_nullifier(&proof_request, None)
        .await?;
    assert_ne!(nullifier.oprf_output(), FieldElement::ZERO);
    // reused below for the session-bound proof; `generate_proof` does not contact the nodes
    let nullifier_for_binding = nullifier.clone();

    let credentials = [CredentialInput {
        credential: credential.clone(),
        blinding_factor: credential_sub_blinding_factor,
    }];

    let result = authenticator
        .generate_proof(&proof_request, nullifier, &credentials, None, None)
        .await?;
    info!("generated uniqueness proof");

    let response_item = &result.proof_response.responses[0];
    assert!(response_item.nullifier.is_some());

    // verify proof with verifier contract
    let request_item = &proof_request.requests[0];
    let world_id_verifier: WorldIDVerifierV2::WorldIDVerifierV2Instance<
        alloy::providers::DynProvider,
    > = WorldIDVerifierV2::new(world_id_verifier, anvil.provider()?);
    world_id_verifier
        .verify(
            response_item
                .nullifier
                .expect("uniqueness proof should have nullifier")
                .into(),
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
            response_item.proof.as_ethereum_representation(),
        )
        .call()
        .await?;
    info!("on-chain proof verification succeeded");

    // ── UNIQUENESS + CREATE (atomic session mint and bound uniqueness proof) ──
    let mut rng = rand::thread_rng();
    let create_nonce = FieldElement::random(&mut rng);
    let create_msg = world_id_primitives::rp::compute_rp_signature_msg(
        *create_nonce,
        rp_fixture.current_timestamp,
        rp_fixture.expiration_timestamp,
        Some(rp_fixture.action),
    );
    let create_signature = LocalSigner::from_signing_key(rp_fixture.signing_key.clone())
        .sign_message_sync(&create_msg)?;
    let create_request = ProofRequest {
        id: "test_uniqueness_create".to_string(),
        session_id: SessionRef::Create,
        action: Some(rp_fixture.action.into()),
        nonce: create_nonce,
        signature: create_signature,
        ..proof_request.clone()
    };
    let create_nullifier = authenticator
        .generate_nullifier(&create_request, None)
        .await?;
    let create_result = authenticator
        .generate_proof(&create_request, create_nullifier, &credentials, None, None)
        .await?;
    let created_session_id = create_result
        .proof_response
        .session_id
        .expect("uniqueness create must mint a session id");
    let created_session_seed = create_result
        .session_id_r_seed
        .expect("uniqueness create must return session seed");
    let create_item = &create_result.proof_response.responses[0];
    assert!(create_item.nullifier.is_some());
    assert!(create_item.session_nullifier.is_none());
    assert_eq!(
        SessionId::from_r_seed(
            leaf_index,
            created_session_seed,
            created_session_id.oprf_seed
        )?,
        created_session_id
    );

    let create_nullifier = create_item
        .nullifier
        .expect("create uniqueness proof should have nullifier");
    let unbound_verify = world_id_verifier
        .verify(
            create_nullifier.into(),
            rp_fixture.action.into(),
            rp_fixture.world_rp_id.into_inner(),
            create_nonce.into(),
            request_item.signal_hash().into(),
            create_item.expires_at_min,
            issuer_schema_id,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            create_item.proof.as_ethereum_representation(),
        )
        .call()
        .await;
    assert!(
        unbound_verify.is_err(),
        "create-bound proof must not verify with sessionId = 0"
    );

    world_id_verifier
        .verifyWithSession(
            create_nullifier.into(),
            rp_fixture.action.into(),
            rp_fixture.world_rp_id.into_inner(),
            create_nonce.into(),
            request_item.signal_hash().into(),
            create_item.expires_at_min,
            issuer_schema_id,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            created_session_id.commitment.into(),
            create_item.proof.as_ethereum_representation(),
        )
        .call()
        .await?;
    info!("uniqueness create proof verified via verifyWithSession");

    // ── SESSION-BOUND UNIQUENESS PROOF (existing session) ──
    let session_id_r_seed = created_session_seed;
    let session_id = created_session_id;
    let bound_request = ProofRequest {
        session_id: SessionRef::Existing(session_id),
        ..proof_request.clone()
    };

    // The seed can be re-derived when it is not cached.
    let uncached_bound_result = authenticator
        .generate_proof(
            &bound_request,
            nullifier_for_binding.clone(),
            &credentials,
            None,
            None,
        )
        .await?;
    assert_eq!(
        uncached_bound_result.session_id_r_seed,
        Some(session_id_r_seed)
    );
    assert_eq!(
        uncached_bound_result.proof_response.session_id,
        Some(session_id)
    );

    // a seed that does not open the session's commitment is rejected
    let err = authenticator
        .generate_proof(
            &bound_request,
            nullifier_for_binding.clone(),
            &credentials,
            None,
            Some(FieldElement::random(&mut rng)),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthenticatorError::SessionIdMismatch));

    let bound_result = authenticator
        .generate_proof(
            &bound_request,
            nullifier_for_binding,
            &credentials,
            None,
            Some(session_id_r_seed),
        )
        .await?;
    info!("generated session-bound uniqueness proof");

    assert_eq!(bound_result.proof_response.session_id, Some(session_id));
    let bound_item = &bound_result.proof_response.responses[0];
    assert!(bound_item.session_nullifier.is_none());
    let bound_nullifier = bound_item
        .nullifier
        .expect("bound proof is a uniqueness proof");
    // same RP/action => same deterministic nullifier as the unbound proof
    assert_eq!(bound_nullifier, response_item.nullifier.unwrap());

    // `verify()` pins the sessionId signal to 0, so it must reject the bound proof
    let unbound_verify = world_id_verifier
        .verify(
            bound_nullifier.into(),
            rp_fixture.action.into(),
            rp_fixture.world_rp_id.into_inner(),
            rp_fixture.nonce.into(),
            request_item.signal_hash().into(),
            bound_item.expires_at_min,
            issuer_schema_id,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            bound_item.proof.as_ethereum_representation(),
        )
        .call()
        .await;
    assert!(
        unbound_verify.is_err(),
        "bound proof must not verify with sessionId = 0"
    );
    info!("session-bound proof correctly rejected by the sessionId=0 entry point");

    // `verifyWithSession` checks the sessionId signal against the session's commitment
    world_id_verifier
        .verifyWithSession(
            bound_nullifier.into(),
            rp_fixture.action.into(),
            rp_fixture.world_rp_id.into_inner(),
            rp_fixture.nonce.into(),
            request_item.signal_hash().into(),
            bound_item.expires_at_min,
            issuer_schema_id,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            session_id.commitment.into(),
            bound_item.proof.as_ethereum_representation(),
        )
        .call()
        .await?;
    info!("session-bound proof verified via verifyWithSession");

    indexer_handle.abort();
    info!("e2e_authenticator_generate_proof finished successfully");
    Ok(())
}

// Solidity fixture generation has been moved to a standalone binary.
// Run with: cargo run -p generate-solidity-fixtures
