//! Generates Solidity test fixtures for `WorldIDVerifierTest.t.sol`.
//!
//! Spins up a local Anvil node, gateway, OPRF nodes, and indexer stub, then
//! produces both a Uniqueness proof and a Session proof. Prints all values
//! needed to update the hardcoded fixtures in the Solidity test (including mock
//! contract return values).
//!
//! Run with:
//! ```sh
//! cargo run -p generate-solidity-fixtures
//! ```

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
use tracing::info;
use tracing_subscriber::EnvFilter;
use world_id_core::{
    Authenticator, EdDSAPrivateKey,
    requests::{ProofRequest, RequestItem, RequestVersion},
};
use world_id_gateway::{GatewayConfig, OrphanSweeperConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_primitives::{Config, FieldElement, TREE_DEPTH, merkle::AccountInclusionProof};
use world_id_test_utils::{
    anvil::WorldIDVerifier,
    fixtures::{
        MerkleFixture, RegistryTestContext, build_base_credential, generate_rp_fixture,
        single_leaf_merkle_fixture,
    },
    stubs::spawn_indexer_stub,
};

fn load_embedded_materials() -> (
    Arc<world_id_core::proof::CircomGroth16Material>,
    Arc<world_id_core::proof::CircomGroth16Material>,
) {
    let query_material = world_id_core::proof::load_embedded_query_material().unwrap();
    let nullifier_material = world_id_core::proof::load_embedded_nullifier_material().unwrap();
    (Arc::new(query_material), Arc::new(nullifier_material))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

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
    let gw_port: u16 = 4105;
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
        sweeper_interval_secs: OrphanSweeperConfig::default().interval_secs,
        stale_queued_threshold_secs: OrphanSweeperConfig::default().stale_queued_threshold_secs,
        stale_submitted_threshold_secs: OrphanSweeperConfig::default()
            .stale_submitted_threshold_secs,
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
        signature: rp_fixture.signature,
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
    info!("Verifying uniqueness proof on-chain...");
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
    info!("Uniqueness proof verified ✓");

    // ── SESSION PROOF (reuse cloned OPRF data with a non-zero session_id) ──
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
    info!("Verifying session proof on-chain...");
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
    info!("Session proof verified ✓");

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

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        SOLIDITY TEST FIXTURE – WorldIDVerifierTest.t.sol    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    println!("// ── Constants ──");
    println!(
        "uint64 constant credentialIssuerIdCorrect = {};",
        issuer_schema_id
    );
    println!(
        "uint64 constant rpIdCorrect = {:#x};",
        rp_fixture.world_rp_id.into_inner()
    );
    println!("uint256 constant rootCorrect = {:#x};", root_u256);
    println!();

    println!("// ── OprfKeyRegistryMock (rpIdCorrect branch) ──");
    println!("x: {:#x},", oprf_pk_x);
    println!("y: {:#x}", oprf_pk_y);
    println!();

    println!("// ── CredentialSchemaIssuerRegistryMock (credentialIssuerIdCorrect branch) ──");
    println!("x: {:#x},", issuer_pk_x);
    println!("y: {:#x}", issuer_pk_y);
    println!();

    println!("// ── Uniqueness Proof inputs ──");
    println!("uint256 nullifier = {:#x};", nullifier_u256);
    println!(
        "uint64 expiresAtMin = {:#x};",
        uniqueness_response.expires_at_min
    );
    println!("uint256 action = {:#x};", action_u256);
    println!("uint256 signalHash = {:#x};", signal_hash_u256);
    println!("uint256 nonce = {:#x};", nonce_u256);

    println!();
    println!("uint256[5] proof = [");
    println!("    {:#x},", u_proof[0]);
    println!("    {:#x},", u_proof[1]);
    println!("    {:#x},", u_proof[2]);
    println!("    {:#x},", u_proof[3]);
    println!("    rootCorrect");
    println!("];");
    println!();

    println!("// ── Session Proof inputs ──");
    let session_id_u256: U256 = session_id.into();
    let s_proof = session_response.proof.as_ethereum_representation();
    let s_null = session_nullifier.as_ethereum_representation();
    println!("uint256 sessionId = {:#x};", session_id_u256);
    println!(
        "uint64 sessionExpiresAtMin = {:#x};",
        session_response.expires_at_min
    );

    println!();
    println!("uint256[5] sessionProof = [");
    println!("    {:#x},", s_proof[0]);
    println!("    {:#x},", s_proof[1]);
    println!("    {:#x},", s_proof[2]);
    println!("    {:#x},", s_proof[3]);
    println!("    rootCorrect");
    println!("];");
    println!();

    println!("// session nullifier for verifySession: [nullifier, action]");
    println!("[{:#x}, {:#x}]", s_null[0], s_null[1]);

    println!();
    println!("// ── Done ──");

    indexer_handle.abort();
    Ok(())
}
