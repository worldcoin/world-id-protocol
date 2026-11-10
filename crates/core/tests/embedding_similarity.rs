#![cfg(feature = "authenticator")]
#![recursion_limit = "256"]

//! WIP-202 end to end: generate a Proof of Embedding Similarity from a Flamingo
//! Verifier result (unbilled), verify it as an RP (§4.8), and check the billed-token witness.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Bytes, U160},
    signers::{SignerSync as _, local::LocalSigner},
};
use eyre::{Result, eyre};
use sha2::{Digest as _, Sha256};
use taceo_oprf::{
    dev_client::health_checks,
    types::{OprfKeyId, ShareEpoch},
};
use tracing::info;
use tracing_subscriber::EnvFilter;
use world_id_core::{
    Authenticator, AuthenticatorError, CredentialInput, EdDSAPrivateKey, FlamingoResult,
    artifacts::{ZkArtifactSource, ZkArtifactSourceExt as _},
    embedding_similarity::{
        AatPolicy, EmbeddingSimilarityPolicy, EmbeddingSimilarityVerificationError as VerifyError,
        FlamingoAttestationVerifier, verify_embedding_similarity,
    },
    requests::{ProofRequest, ProofType, RequestItem, RequestVersion},
};
use world_id_flamingo::{FlamingoClaims, FlamingoToken, engine_config_hash};
use world_id_gateway::{
    BatchPolicyConfig, GatewayConfig, RegistryVersion, SignerArgs, defaults,
    spawn_gateway_for_tests,
};
use world_id_primitives::{
    Config, EmbeddingSimilarityParams, FieldElement, OprfPrefix, OprfPrefixedFieldElement as _,
    ServiceEndpoint, SessionRef, TREE_DEPTH, merkle::AccountInclusionProof,
};
use world_id_proof::embedding_similarity_proof::COMPARE_SOURCES;
use world_id_test_utils::{
    fixtures::{
        MerkleFixture, RegistryTestContext, build_base_credential, generate_rp_fixture,
        single_leaf_merkle_fixture,
    },
    redis_testcontainer,
    stubs::{spawn_indexer_stub, spawn_oprf_nodes},
};

fn zk_artifact_source() -> Arc<dyn ZkArtifactSource> {
    Arc::new(world_id_core::artifacts::embedded::EmbeddedZkArtifacts.cached())
}

fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}

/// `R(SHA-256(bytes))`, how WIP-201 lowers an image digest into the field.
fn image_hash(bytes: &[u8]) -> FieldElement {
    FieldElement::from_digest(&Sha256::digest(bytes).into())
}

/// A compact, key-sorted PCP `hashes.json` (WIP-202 §4.1) whose `thumbnail.png` is `thumbnail`,
/// padded with other files to the circuit's minimum length.
fn hashes_json(thumbnail: &[u8]) -> Vec<u8> {
    let mut entries: std::collections::BTreeMap<String, String> = (0..48)
        .map(|i| {
            let name = format!("file_{i:02}.bin");
            let digest = hex::encode(Sha256::digest(name.as_bytes()));
            (name, digest)
        })
        .collect();
    entries.insert(
        "thumbnail.png".into(),
        hex::encode(Sha256::digest(thumbnail)),
    );
    entries.insert("version".into(), "3.0".into());
    let body = entries
        .iter()
        .map(|(key, value)| format!("\"{key}\":\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}").into_bytes()
}

/// The Flamingo Verifier's result for `proof_request`, comparing the thumbnail, a live capture
/// and the challenge under the WIP-202 entry layout (§4.3).
fn flamingo_result(
    proof_request: &ProofRequest,
    thumbnail: &[u8],
    challenge_hash: FieldElement,
    billing_nullifier: FieldElement,
) -> Result<FlamingoResult> {
    let verifier_sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let claims = FlamingoClaims {
        now: u32::try_from(now_secs())?,
        compared_entry_hashes: [
            image_hash(thumbnail),
            image_hash(b"live capture"),
            challenge_hash,
            FieldElement::ZERO,
        ],
        aud: proof_request.rp_id.into(),
        nonce: proof_request.nonce,
        aat: None,
        compare_sources: COMPARE_SOURCES,
        engine_config_hash: engine_config_hash(&[0xE7; 32], 1, 2),
        billing_nullifier,
    };
    // Through the CWT encoding, as the token reaches the Authenticator.
    let token = FlamingoToken::sign(claims, &verifier_sk)?.to_cwt()?;
    Ok(FlamingoResult {
        token: FlamingoToken::from_cwt(&token)?,
        verifier_key: verifier_sk.public(),
        signing_key_attestation: Bytes::from(verifier_sk.public().to_compressed_bytes()?.to_vec()),
    })
}

/// Stands in for the Nitro check: the attestation is the attested key itself.
#[derive(Clone)]
struct StubAttestation;

impl FlamingoAttestationVerifier for StubAttestation {
    fn attested_key(&self, attestation: &[u8]) -> Result<world_id_core::EdDSAPublicKey, String> {
        let key: [u8; 32] = attestation
            .try_into()
            .map_err(|_| "not a key".to_string())?;
        world_id_core::EdDSAPublicKey::from_compressed_bytes(key).map_err(|e| e.to_string())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_embedding_similarity_proof() -> Result<()> {
    init_test_tracing();
    info!("starting e2e_embedding_similarity_proof");
    let mut rng = rand::thread_rng();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    // Registries on Anvil (no Billing Contract; this path is unbilled).
    let RegistryTestContext {
        anvil,
        world_id_registry,
        rp_registry,
        oprf_key_registry,
        world_id_verifier: _,
        credential_registry,
    } = RegistryTestContext::new().await?;
    let deployer = anvil.signer(0)?;
    let chain_id = anvil.instance.chain_id();

    // Gateway for account creation.
    let (_redis, redis_url) = redis_testcontainer().await?;
    let gateway = spawn_gateway_for_tests(GatewayConfig {
        registry_addr: world_id_registry,
        registry_version: RegistryVersion::V2,
        billing_addr: None,
        provider: world_id_gateway::ProviderArgs {
            http: vec![anvil.endpoint().parse().unwrap()],
            signer: SignerArgs::from_wallet(hex::encode(deployer.to_bytes())),
            ..Default::default()
        },
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url,
        request_timeout_secs: 10,
        rate_limit_max_requests: None,
        rate_limit_window_secs: None,
        sweeper_interval_secs: defaults::SWEEPER_INTERVAL_SECS,
        stale_queued_threshold_secs: defaults::STALE_QUEUED_THRESHOLD_SECS,
        stale_submitted_threshold_secs: defaults::STALE_SUBMITTED_THRESHOLD_SECS,
        batch_policy: BatchPolicyConfig::default(),
    })
    .await
    .map_err(|e| eyre!("failed to spawn gateway for tests: {e}"))?;
    let gateway_url = format!("http://{}", gateway.listen_addr);

    // Account, created through the gateway.
    let seed = [13u8; 32];
    let creation_config = Config::new(
        Some(anvil.endpoint().to_string()),
        chain_id,
        world_id_registry,
        ServiceEndpoint::direct("http://127.0.0.1:0".to_string()),
        ServiceEndpoint::direct(gateway_url.clone()),
        Vec::new(),
        3,
    )
    .unwrap();
    let authenticator = Authenticator::init_or_register(
        &seed,
        creation_config,
        Some(anvil.signer(1)?.address()),
        zk_artifact_source(),
    )
    .await?;
    let leaf_index = authenticator.leaf_index();

    // Indexer stub serving the account's inclusion proof.
    let MerkleFixture {
        key_set,
        inclusion_proof,
        root: merkle_root,
        ..
    } = single_leaf_merkle_fixture(vec![authenticator.offchain_pubkey()], leaf_index)?;
    let (indexer_url, _indexer) = spawn_indexer_stub(
        leaf_index,
        AccountInclusionProof::<{ TREE_DEPTH }>::new(inclusion_proof, key_set),
    )
    .await?;

    // OPRF nodes for credential blinding.
    let connection_string = world_id_test_utils::shared_postgres_testcontainer().await?;
    let secret_managers =
        world_id_test_utils::stubs::init_test_secret_managers(connection_string.to_string().into())
            .await?;
    let key_gens =
        world_id_test_utils::stubs::spawn_key_gens(&anvil, connection_string, oprf_key_registry)
            .await?;
    let nodes = spawn_oprf_nodes(
        &anvil,
        secret_managers,
        world_id_registry,
        rp_registry,
        credential_registry,
    )
    .await;
    health_checks::services_health_check(&nodes, Duration::from_secs(60)).await?;
    health_checks::services_health_check(&key_gens.urls, Duration::from_secs(60)).await?;

    // Issuer and RP, each with an OPRF key.
    let issuer_schema_id = 1u64;
    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    anvil
        .register_issuer(
            credential_registry,
            deployer.clone(),
            issuer_schema_id,
            issuer_sk.public(),
        )
        .await?;
    let rp_fixture = generate_rp_fixture();
    let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
    anvil
        .register_rp(
            rp_registry,
            deployer.clone(),
            rp_fixture.world_rp_id,
            rp_signer.address(),
            rp_signer.address(),
            "poes.rp".to_string(),
        )
        .await?;
    for key_id in [
        rp_fixture.oprf_key_id,
        OprfKeyId::new(U160::from(issuer_schema_id)),
    ] {
        health_checks::oprf_public_key_from_services(
            key_id,
            ShareEpoch::default(),
            &nodes,
            Duration::from_secs(120),
        )
        .await?;
    }

    // Authenticator pointed at the indexer, gateway and OPRF nodes.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_current_dir(&workspace_root)?;
    let authenticator = Authenticator::init(
        &seed,
        Config::new(
            Some(anvil.endpoint().to_string()),
            chain_id,
            world_id_registry,
            ServiceEndpoint::direct(indexer_url),
            ServiceEndpoint::direct(gateway_url),
            nodes.to_vec(),
            3,
        )
        .unwrap(),
        zk_artifact_source(),
    )
    .await?;

    // PoH Credential whose claim 0 commits to the PCP's `hashes.json`.
    let now = now_secs();
    let blinding_factor = authenticator
        .generate_credential_blinding_factor(issuer_schema_id)
        .await?;
    let thumbnail = b"orb thumbnail".as_slice();
    let hashes_json = hashes_json(thumbnail);
    let mut credential = build_base_credential(
        issuer_schema_id,
        leaf_index,
        now,
        now + 3_600,
        blinding_factor,
    )
    .claim(0, &hashes_json)?;
    credential.issuer = issuer_sk.public();
    credential.signature = Some(issuer_sk.sign(*credential.hash()?));
    let credential = CredentialInput {
        credential,
        blinding_factor,
    };

    // RP-signed Proof of Embedding Similarity request.
    let action = FieldElement::random_with_prefix(&mut rng, OprfPrefix::EmbeddingSimilarity);
    let nonce = FieldElement::random(&mut rng);
    let challenge_hash = image_hash(b"meeting frame");
    let created_at = now_secs();
    let expires_at = created_at + 300;
    let signature =
        rp_signer.sign_message_sync(&world_id_primitives::rp::compute_rp_signature_msg(
            *nonce,
            created_at,
            expires_at,
            Some(*action),
        ))?;
    let proof_request = ProofRequest {
        id: "embedding_similarity_request".to_string(),
        version: RequestVersion::V1,
        proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
            action,
            challenge_hash,
            aat: None,
        }),
        created_at,
        expires_at,
        rp_id: rp_fixture.world_rp_id,
        oprf_key_id: rp_fixture.oprf_key_id,
        session_id: SessionRef::None,
        signature,
        nonce,
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id,
            signal: Some(b"meeting-42".to_vec()),
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    };

    // Unbilled Flamingo result: prove.
    let unbilled = flamingo_result(
        &proof_request,
        thumbnail,
        challenge_hash,
        FieldElement::ZERO,
    )?;
    let response = authenticator
        .generate_embedding_similarity_proof(
            &proof_request,
            &unbilled,
            &credential,
            &hashes_json,
            None,
            None,
            None,
        )
        .await?
        .proof_response;

    // The RP verifies it under WIP-202 §4.8.
    let artifacts = zk_artifact_source();
    let policy = EmbeddingSimilarityPolicy {
        attestation: StubAttestation,
        engine_config_hashes: [engine_config_hash(&[0xE7; 32], 1, 2)].into(),
        issuer_version: credential.credential.issuer_version,
        issuer_keys: vec![issuer_sk.public()],
        aat: AatPolicy::default(),
    };
    let valid_root = move |root| async move { Ok::<_, std::io::Error>(root == merkle_root) };
    let verify = async |request: &ProofRequest,
                        response: &world_id_primitives::ProofResponse,
                        policy: &EmbeddingSimilarityPolicy<StubAttestation>,
                        now: u64| {
        verify_embedding_similarity(
            request,
            response,
            policy,
            now,
            valid_root,
            artifacts.as_ref(),
        )
        .await
    };
    verify(&proof_request, &response, &policy, now_secs()).await?;

    // Each policy check rejects on its own, before the proof is verified.
    let mut other_engine = policy.clone();
    other_engine.engine_config_hashes = [FieldElement::from(1u64)].into();
    let mut other_issuer = policy.clone();
    other_issuer.issuer_keys = vec![EdDSAPrivateKey::random(&mut rng).public()];
    let mut aat_required = policy.clone();
    aat_required.aat.required = true;
    for (policy, now, expected) in [
        (&other_engine, now_secs(), "EngineNotAccepted"),
        (&other_issuer, now_secs(), "UntrustedIssuerKey"),
        (&aat_required, now_secs(), "AatRequired"),
        (&policy, now_secs() + 3_600, "RequestExpired"),
        (&policy, now_secs() - 600, "Stale"),
    ] {
        let err = verify(&proof_request, &response, policy, now)
            .await
            .expect_err(expected);
        assert!(format!("{err:?}").starts_with(expected), "{err:?}");
    }
    let mut other_attestation = response.clone();
    other_attestation
        .embedding_similarity
        .as_mut()
        .ok_or_else(|| eyre!("no embedding similarity item"))?
        .signing_key_attestation = Bytes::from(
        EdDSAPrivateKey::random(&mut rng)
            .public()
            .to_compressed_bytes()?
            .to_vec(),
    );
    assert!(matches!(
        verify(&proof_request, &other_attestation, &policy, now_secs()).await,
        Err(VerifyError::AttestedKeyMismatch)
    ));
    let unknown_root = |_| async { Ok::<_, std::io::Error>(false) };
    assert!(matches!(
        verify_embedding_similarity(
            &proof_request,
            &response,
            &policy,
            now_secs(),
            unknown_root,
            artifacts.as_ref(),
        )
        .await,
        Err(VerifyError::InvalidRoot(_))
    ));
    let unreachable_registry = |_| async { Err::<bool, _>(std::io::Error::other("registry down")) };
    assert!(matches!(
        verify_embedding_similarity(
            &proof_request,
            &response,
            &policy,
            now_secs(),
            unreachable_registry,
            artifacts.as_ref(),
        )
        .await,
        Err(VerifyError::RootCheck(_))
    ));

    // The proof binds the RP's request: another challenge fails the proof itself.
    let mut other_challenge = proof_request.clone();
    other_challenge.proof_type = ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
        action,
        challenge_hash: image_hash(b"another frame"),
        aat: None,
    });
    assert!(matches!(
        verify(&other_challenge, &response, &policy, now_secs()).await,
        Err(VerifyError::Proof(_))
    ));

    // A billed token without a witness is rejected before proving.
    let billed = flamingo_result(
        &proof_request,
        thumbnail,
        challenge_hash,
        FieldElement::from(7u64),
    )?;
    let err = authenticator
        .generate_embedding_similarity_proof(
            &proof_request,
            &billed,
            &credential,
            &hashes_json,
            None,
            None,
            None,
        )
        .await
        .expect_err("a billed token needs the billing witness");
    assert!(
        matches!(err, AuthenticatorError::BillingWitnessRequired),
        "{err}"
    );

    gateway.shutdown().await.ok();
    info!("e2e_embedding_similarity_proof finished successfully");
    Ok(())
}
