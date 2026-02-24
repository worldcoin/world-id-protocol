#![cfg(feature = "authenticator")]

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{U160, U256},
    signers::local::LocalSigner,
};
use eyre::{Context as _, Result, eyre};
use taceo_oprf::types::{OprfKeyId, ShareEpoch};
use taceo_oprf_test_utils::health_checks;
use world_id_core::{
    Authenticator, AuthenticatorError, EdDSAPrivateKey,
    requests::{ProofRequest, RequestItem, RequestVersion},
};
use world_id_gateway::{GatewayConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_primitives::{Config, FieldElement, TREE_DEPTH, merkle::AccountInclusionProof};
use world_id_test_utils::{
    anvil::WorldIDVerifier,
    fixtures::{
        MerkleFixture, RegistryTestContext, build_base_credential, generate_rp_fixture,
        single_leaf_merkle_fixture,
    },
    stubs::spawn_indexer_stub,
};

const GW_PORT: u16 = 4104;

fn load_embedded_materials() -> (
    Arc<world_id_core::proof::CircomGroth16Material>,
    Arc<world_id_core::proof::CircomGroth16Material>,
) {
    let query_material = world_id_core::proof::load_embedded_query_material().unwrap();
    let nullifier_material = world_id_core::proof::load_embedded_nullifier_material().unwrap();
    (Arc::new(query_material), Arc::new(nullifier_material))
}

/// Generates an entire end-to-end Uniqueness Proof Generator
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    let mut rng = rand::thread_rng();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let RegistryTestContext {
        anvil,
        world_id_registry,
        rp_registry,
        oprf_key_registry,
        world_id_verifier,
        credential_registry,
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
        redis_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
        request_timeout_secs: 10,
        rate_limit_max_requests: None,
        rate_limit_window_secs: None,
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
    let (query_material, nullifier_material) = load_embedded_materials();

    // World ID should not yet exist.
    let init_result = Authenticator::init(
        &seed,
        creation_config.clone(),
        query_material,
        nullifier_material,
    )
    .await;
    assert!(
        matches!(init_result, Err(AuthenticatorError::AccountDoesNotExist)),
        "expected missing account error before creation"
    );

    // Create the account via the gateway, blocking until confirmed.
    let start = SystemTime::now();
    let (query_material, nullifier_material) = load_embedded_materials();
    let authenticator = Authenticator::init_or_register(
        &seed,
        creation_config.clone(),
        query_material,
        nullifier_material,
        Some(recovery_address),
    )
    .await
    .unwrap();
    println!(
        "Authentication creation took: {}ms",
        SystemTime::now().duration_since(start).unwrap().as_millis(),
    );

    assert_eq!(authenticator.leaf_index(), 1);
    assert_eq!(authenticator.recovery_counter(), U256::ZERO);

    // Re-initialize to ensure account metadata is persisted.
    let (query_material, nullifier_material) = load_embedded_materials();
    let authenticator =
        Authenticator::init(&seed, creation_config, query_material, nullifier_material)
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
        AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_inclusion_proof, key_set.clone())
            .wrap_err("failed to build inclusion proof")?;

    let (indexer_url, indexer_handle) = spawn_indexer_stub(leaf_index, inclusion_proof.clone())
        .await
        .wrap_err("failed to start indexer stub")?;

    let rp_fixture = generate_rp_fixture();

    let (key_gen_secret_managers, node_secret_managers) =
        world_id_test_utils::stubs::init_test_secret_managers();

    // OPRF key-gen instances
    let oprf_key_gens = world_id_test_utils::stubs::spawn_key_gens(
        anvil.ws_endpoint(),
        key_gen_secret_managers,
        oprf_key_registry,
    )
    .await;

    // OPRF nodes
    let nodes = world_id_test_utils::stubs::spawn_oprf_nodes(
        anvil.ws_endpoint(),
        node_secret_managers,
        oprf_key_registry,
        world_id_registry,
        rp_registry,
        credential_registry,
    )
    .await;

    health_checks::services_health_check(&nodes, Duration::from_secs(60)).await?;
    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60)).await?;

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

    let (query_material, nullifier_material) = load_embedded_materials();
    let authenticator =
        Authenticator::init(&seed, proof_config, query_material, nullifier_material)
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
        created_at: rp_fixture.current_timestamp,
        expires_at: rp_fixture.expiration_timestamp,
        rp_id: rp_fixture.world_rp_id,
        oprf_key_id: rp_fixture.oprf_key_id,
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

    let (inclusion_proof, key_set) = authenticator.fetch_inclusion_proof().await?;
    let nullifier = authenticator
        .generate_nullifier(&proof_request, inclusion_proof, key_set)
        .await?;
    let raw_nullifier = FieldElement::from(nullifier.verifiable_oprf_output.output);
    assert_ne!(raw_nullifier, FieldElement::ZERO);

    // Generate session_id_r_seed for proof generation
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

    assert_eq!(response_item.nullifier, Some(raw_nullifier));

    // verify proof with verifier contract
    let world_id_verifier: WorldIDVerifier::WorldIDVerifierInstance<alloy::providers::DynProvider> =
        WorldIDVerifier::new(world_id_verifier, anvil.provider()?);
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

    indexer_handle.abort();
    Ok(())
}

/// Generates Solidity test fixtures for WorldIDVerifierTest.t.sol.
///
/// Produces both a Uniqueness proof and a Session proof, then prints all values
/// needed to update the hardcoded fixtures in the Solidity test (including mock
/// contract return values).
///
/// Run with:
/// ```sh
/// cargo test -p world-id-core --test generate_proof generate_solidity_fixtures \
///     --features authenticator -- --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn generate_solidity_fixtures() -> Result<()> {
    let mut rng = rand::thread_rng();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // may already be installed

    let RegistryTestContext {
        anvil,
        world_id_registry,
        rp_registry,
        oprf_key_registry,
        world_id_verifier,
        credential_registry,
    } = RegistryTestContext::new().await?;

    let deployer = anvil
        .signer(0)
        .wrap_err("failed to fetch deployer signer for anvil")?;

    // Spawn the gateway.
    let gw_port: u16 = 4105; // different port to avoid conflicts
    let signer_args = SignerArgs::from_wallet(hex::encode(deployer.to_bytes()));
    let gateway_config = GatewayConfig {
        registry_addr: world_id_registry,
        provider: world_id_gateway::ProviderArgs {
            http: Some(vec![anvil.endpoint().parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, gw_port).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
        request_timeout_secs: 10,
        rate_limit_max_requests: None,
        rate_limit_window_secs: None,
    };
    let _gateway = spawn_gateway_for_tests(gateway_config)
        .await
        .map_err(|e| eyre!("failed to spawn gateway for tests: {e}"))?;

    // Create account.
    let seed = [7u8; 32];
    let recovery_address = anvil
        .signer(1)
        .wrap_err("failed to fetch recovery signer")?
        .address();

    let creation_config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        world_id_registry,
        "http://127.0.0.1:0".to_string(),
        format!("http://127.0.0.1:{gw_port}"),
        Vec::new(),
        3,
    )
    .unwrap();
    let (query_material, nullifier_material) = load_embedded_materials();
    let _authenticator = Authenticator::init_or_register(
        &seed,
        creation_config.clone(),
        query_material,
        nullifier_material,
        Some(recovery_address),
    )
    .await
    .unwrap();

    let (query_material, nullifier_material) = load_embedded_materials();
    let authenticator =
        Authenticator::init(&seed, creation_config, query_material, nullifier_material)
            .await
            .wrap_err("expected authenticator to initialize after account creation")?;

    let leaf_index = authenticator.leaf_index();
    let MerkleFixture {
        key_set,
        inclusion_proof: merkle_inclusion_proof,
        ..
    } = single_leaf_merkle_fixture(vec![authenticator.offchain_pubkey()], leaf_index)
        .wrap_err("failed to construct merkle fixture")?;

    let inclusion_proof =
        AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_inclusion_proof, key_set.clone())
            .wrap_err("failed to build inclusion proof")?;

    let (indexer_url, indexer_handle) = spawn_indexer_stub(leaf_index, inclusion_proof.clone())
        .await
        .wrap_err("failed to start indexer stub")?;

    let rp_fixture = generate_rp_fixture();

    let (key_gen_secret_managers, node_secret_managers) =
        world_id_test_utils::stubs::init_test_secret_managers();

    let oprf_key_gens = world_id_test_utils::stubs::spawn_key_gens(
        anvil.ws_endpoint(),
        key_gen_secret_managers,
        oprf_key_registry,
    )
    .await;

    let nodes = world_id_test_utils::stubs::spawn_oprf_nodes(
        anvil.ws_endpoint(),
        node_secret_managers,
        oprf_key_registry,
        world_id_registry,
        rp_registry,
        credential_registry,
    )
    .await;

    health_checks::services_health_check(&nodes, Duration::from_secs(60)).await?;
    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60)).await?;

    // Register issuer.
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

    // Register RP.
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

    // Wait for key-gens.
    let rp_oprf_public_key = health_checks::oprf_public_key_from_services(
        rp_fixture.oprf_key_id,
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;
    let _issuer_oprf_public_key = health_checks::oprf_public_key_from_services(
        OprfKeyId::new(U160::from(issuer_schema_id)),
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;

    // Set working directory.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_current_dir(&workspace_root)
        .wrap_err("failed to set working directory to workspace root")?;

    let proof_config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        world_id_registry,
        indexer_url.clone(),
        format!("http://127.0.0.1:{gw_port}"),
        nodes.to_vec(),
        3,
    )
    .unwrap();

    let (query_material, nullifier_material) = load_embedded_materials();
    let authenticator =
        Authenticator::init(&seed, proof_config, query_material, nullifier_material)
            .await
            .wrap_err("failed to reinitialize authenticator with proof config")?;

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
    credential.issuer = issuer_pk.clone();
    let credential_hash = credential
        .hash()
        .wrap_err("failed to hash credential prior to signing")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    let signal_str = "my_signal";

    // ── OPRF round for uniqueness proof ──
    let uniqueness_request = ProofRequest {
        id: "fixture_uniqueness".to_string(),
        version: RequestVersion::V1,
        created_at: rp_fixture.current_timestamp,
        expires_at: rp_fixture.expiration_timestamp,
        rp_id: rp_fixture.world_rp_id,
        oprf_key_id: rp_fixture.oprf_key_id,
        session_id: None,
        action: Some(rp_fixture.action.into()),
        signature: rp_fixture.signature.clone(),
        nonce: rp_fixture.nonce.into(),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id,
            signal: Some(signal_str.to_string()),
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    };
    let request_item = uniqueness_request
        .find_request_by_issuer_schema_id(issuer_schema_id)
        .unwrap();

    let (incl_proof, key_set) = authenticator.fetch_inclusion_proof().await?;
    let nullifier_data = authenticator
        .generate_nullifier(&uniqueness_request, incl_proof, key_set)
        .await?;
    // Clone the nullifier data before it's consumed — we reuse it for the session proof.
    // The OPRF output is independent of session_id, so this is safe.
    let nullifier_data_for_session = nullifier_data.clone();

    let session_id_r_seed = FieldElement::random(&mut rng);
    let uniqueness_response = authenticator.generate_single_proof(
        nullifier_data,
        request_item,
        &credential,
        credential_sub_blinding_factor,
        session_id_r_seed,
        uniqueness_request.session_id,
        uniqueness_request.created_at,
    )?;

    // Verify on-chain.
    let verifier_instance: WorldIDVerifier::WorldIDVerifierInstance<alloy::providers::DynProvider> =
        WorldIDVerifier::new(world_id_verifier, anvil.provider()?);
    verifier_instance
        .verify(
            uniqueness_response
                .nullifier
                .expect("uniqueness proof should have nullifier")
                .into(),
            rp_fixture.action.into(),
            rp_fixture.world_rp_id.into_inner(),
            rp_fixture.nonce.into(),
            request_item.signal_hash().into(),
            uniqueness_response.expires_at_min,
            issuer_schema_id,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            uniqueness_response.proof.as_ethereum_representation(),
        )
        .call()
        .await?;

    // ── SESSION PROOF (reuse cloned OPRF data with a non-zero session_id) ──
    // The circuit constrains: id_commitment * (id_commitment - Poseidon2(DS_C, mt_index, id_commitment_r)[1]) === 0
    // So session_id must equal Poseidon2_t3(DS_C, mt_index, session_id_r_seed)[1].
    let session_id_r_seed2 = FieldElement::random(&mut rng);
    let ds_c = ark_babyjubjub::Fq::from(5199521648757207593u64); // b"H(id, r)"
    let mt_index = ark_babyjubjub::Fq::from(leaf_index);
    let mut id_state = [ds_c, mt_index, *session_id_r_seed2];
    poseidon2::bn254::t3::permutation_in_place(&mut id_state);
    let session_id: FieldElement = id_state[1].into();
    let session_response = authenticator.generate_single_proof(
        nullifier_data_for_session,
        request_item,
        &credential,
        credential_sub_blinding_factor,
        session_id_r_seed2,
        Some(session_id),
        uniqueness_request.created_at,
    )?;

    let session_nullifier = session_response
        .session_nullifier
        .expect("session proof should have session_nullifier");

    // Verify session proof on-chain.
    verifier_instance
        .verifySession(
            rp_fixture.world_rp_id.into_inner(),
            rp_fixture.nonce.into(),
            request_item.signal_hash().into(),
            session_response.expires_at_min,
            issuer_schema_id,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            session_id.into(),
            session_nullifier.as_ethereum_representation(),
            session_response.proof.as_ethereum_representation(),
        )
        .call()
        .await?;

    // ── PRINT SOLIDITY FIXTURE ──
    let u_proof = uniqueness_response.proof.as_ethereum_representation();

    // Derive the OPRF public key coordinates as U256 via FieldElement conversion.
    let oprf_pk_point = rp_oprf_public_key.inner();
    let oprf_pk_x: U256 = FieldElement::from(oprf_pk_point.x).into();
    let oprf_pk_y: U256 = FieldElement::from(oprf_pk_point.y).into();

    let issuer_pk_x: U256 = FieldElement::from(issuer_pk.pk.x).into();
    let issuer_pk_y: U256 = FieldElement::from(issuer_pk.pk.y).into();

    let nullifier_u256: U256 = uniqueness_response
        .nullifier
        .expect("uniqueness proof has nullifier")
        .into();
    let action_u256: U256 = FieldElement::from(rp_fixture.action).into();
    let nonce_u256: U256 = FieldElement::from(rp_fixture.nonce).into();
    let signal_hash_u256: U256 = request_item.signal_hash().into();
    let root_u256 = u_proof[4]; // last element is merkle root

    eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║        SOLIDITY TEST FIXTURE – WorldIDVerifierTest.t.sol    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝\n");

    eprintln!("// ── Constants ──");
    eprintln!(
        "uint64 constant credentialIssuerIdCorrect = {};",
        issuer_schema_id
    );
    eprintln!(
        "uint64 constant rpIdCorrect = {:#x};",
        rp_fixture.world_rp_id.into_inner()
    );
    eprintln!("uint256 constant rootCorrect = {:#x};\n", root_u256);

    eprintln!("// ── OprfKeyRegistryMock (rpIdCorrect branch) ──");
    eprintln!("x: {:#x},", oprf_pk_x);
    eprintln!("y: {:#x}\n", oprf_pk_y);

    eprintln!("// ── CredentialSchemaIssuerRegistryMock (credentialIssuerIdCorrect branch) ──");
    eprintln!("x: {:#x},", issuer_pk_x);
    eprintln!("y: {:#x}\n", issuer_pk_y);

    eprintln!("// ── Uniqueness Proof inputs ──");
    eprintln!("uint256 nullifier = {:#x};", nullifier_u256);
    eprintln!(
        "uint64 expiresAtMin = {:#x};",
        uniqueness_response.expires_at_min
    );
    eprintln!("uint256 action = {:#x};", action_u256);
    eprintln!("uint256 signalHash = {:#x};", signal_hash_u256);
    eprintln!("uint256 nonce = {:#x};", nonce_u256);

    eprintln!("\nuint256[5] proof = [");
    eprintln!("    {:#x},", u_proof[0]);
    eprintln!("    {:#x},", u_proof[1]);
    eprintln!("    {:#x},", u_proof[2]);
    eprintln!("    {:#x},", u_proof[3]);
    eprintln!("    rootCorrect");
    eprintln!("];\n");

    eprintln!("// ── Session Proof inputs ──");
    let session_id_u256: U256 = session_id.into();
    let s_proof = session_response.proof.as_ethereum_representation();
    let s_null = session_nullifier.as_ethereum_representation();
    eprintln!("uint256 sessionId = {:#x};", session_id_u256);
    eprintln!(
        "uint64 sessionExpiresAtMin = {:#x};",
        session_response.expires_at_min
    );

    eprintln!("\nuint256[5] sessionProof = [");
    eprintln!("    {:#x},", s_proof[0]);
    eprintln!("    {:#x},", s_proof[1]);
    eprintln!("    {:#x},", s_proof[2]);
    eprintln!("    {:#x},", s_proof[3]);
    eprintln!("    rootCorrect");
    eprintln!("];\n");

    eprintln!("// session nullifier for verifySession: [nullifier, action]");
    eprintln!("[{:#x}, {:#x}]", s_null[0], s_null[1]);

    eprintln!("\n// ── Done ──");

    indexer_handle.abort();
    Ok(())
}
