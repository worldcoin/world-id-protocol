#![cfg(feature = "authenticator")]
#![recursion_limit = "256"]

//! WIP-107 and WIP-202 end to end: a billing query through the OPRF nodes, the registration proof
//! and its relay through the gateway to `WorldIDBilling.register`, then the Proof of Embedding
//! Similarity over a billed Flamingo Token.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Bytes, U160, U256},
    signers::{SignerSync as _, local::LocalSigner},
};
use eyre::{Result, bail, eyre};
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
    requests::{ProofRequest, ProofType, RequestItem, RequestVersion},
};
use world_id_flamingo::{FlamingoClaims, FlamingoToken, engine_config_hash};
use world_id_gateway::{
    BatchPolicyConfig, GatewayConfig, RegistryVersion, SignerArgs, defaults,
    spawn_gateway_for_tests,
};
use world_id_oprf_node::config::BillingContractConfig;
use world_id_primitives::{
    Config, EmbeddingSimilarityParams, FieldElement, OprfPrefix, OprfPrefixedFieldElement as _,
    ServiceEndpoint, SessionRef, TREE_DEPTH,
    api_types::{GatewayErrorCode, GatewayRequestState},
    billing::{BillingContext, active_periods, registration_period_start},
    merkle::AccountInclusionProof,
};
use world_id_proof::{
    circuit_inputs::EmbeddingSimilarityRequestInputs,
    embedding_similarity_proof::{COMPARE_SOURCES, verify_embedding_similarity_proof},
};
use world_id_registries::world_id_billing::WorldIdBilling;
use world_id_test_utils::{
    anvil::world_id_billing::IWorldIDBilling,
    fixtures::{
        MerkleFixture, RegistryTestContext, build_base_credential, generate_rp_fixture,
        single_leaf_merkle_fixture,
    },
    redis_testcontainer,
    stubs::{spawn_indexer_stub, spawn_oprf_nodes_with_billing},
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
        signing_key_attestation: Bytes::from_static(b"attestation"),
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_billing_registration() -> Result<()> {
    init_test_tracing();
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
    let deployer = anvil.signer(0)?;
    let chain_id = anvil.instance.chain_id();
    let billing = anvil
        .deploy_world_id_billing(deployer.clone(), world_id_verifier, rp_registry)
        .await?;
    info!(billing = ?billing.billing, "billing contract deployed");

    // Gateway relaying registrations to the Billing Contract.
    let (_redis, redis_url) = redis_testcontainer().await?;
    let gateway = spawn_gateway_for_tests(GatewayConfig {
        registry_addr: world_id_registry,
        registry_version: RegistryVersion::V2,
        billing_addr: Some(billing.billing),
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
    let seed = [11u8; 32];
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

    let MerkleFixture {
        key_set,
        inclusion_proof,
        ..
    } = single_leaf_merkle_fixture(vec![authenticator.offchain_pubkey()], leaf_index)?;
    let (indexer_url, _indexer) = spawn_indexer_stub(
        leaf_index,
        AccountInclusionProof::<{ TREE_DEPTH }>::new(inclusion_proof, key_set),
    )
    .await?;

    // OPRF nodes accepting billing queries for this Billing Contract.
    let connection_string = world_id_test_utils::shared_postgres_testcontainer().await?;
    let secret_managers =
        world_id_test_utils::stubs::init_test_secret_managers(connection_string.to_string().into())
            .await?;
    let key_gens =
        world_id_test_utils::stubs::spawn_key_gens(&anvil, connection_string, oprf_key_registry)
            .await?;
    let nodes = spawn_oprf_nodes_with_billing(
        &anvil,
        secret_managers,
        world_id_registry,
        rp_registry,
        credential_registry,
        Some(BillingContractConfig::new(chain_id, billing.billing)),
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
            "billed.rp".to_string(),
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

    // The RP buys capacity for the current period only.
    let now = now_secs();
    let active = active_periods(now)?;
    let scope = BillingContext {
        chain_id: U256::from(chain_id),
        billing_contract: billing.billing,
        rp_id: rp_fixture.world_rp_id,
        period_start: registration_period_start(active, false),
    };
    anvil
        .purchase_billing_capacity(
            deployer.clone(),
            billing,
            IWorldIDBilling::BillingContext {
                chainId: scope.chain_id,
                billingContract: scope.billing_contract,
                rpId: scope.rp_id.into_inner(),
                periodStart: scope.period_start,
            },
            1,
        )
        .await?;

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

    let blinding_factor = authenticator
        .generate_credential_blinding_factor(issuer_schema_id)
        .await?;
    // A PoH Credential whose claim 0 commits to the PCP's `hashes.json`.
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

    // A Proof of Embedding Similarity request with a billed (0x03) action, signed by the RP.
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
        id: "billing_request".to_string(),
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

    // Billing query, registration proof, and relay.
    let billing_query = authenticator
        .generate_billing_nullifier(&proof_request, &scope, now_secs(), None)
        .await?;
    let witness = billing_query.billing_witness();
    let registration = authenticator.generate_billing_registration(
        &proof_request,
        &scope,
        billing_query,
        &credential,
    )?;
    assert_eq!(registration.billing_nullifier, witness.billing_nullifier);
    let request_id = authenticator
        .submit_billing_registration(&registration)
        .await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match authenticator.poll_status(&request_id).await? {
            GatewayRequestState::Finalized { tx_hash } => {
                info!(tx_hash, "billing registration finalized");
                break;
            }
            GatewayRequestState::Failed { error, error_code } => {
                bail!("billing registration failed ({error_code:?}): {error}");
            }
            _ if tokio::time::Instant::now() > deadline => {
                bail!("billing registration did not finalize in time");
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }

    let contract = WorldIdBilling::new(billing.billing, anvil.provider()?);
    assert!(
        contract
            .isRegistered(registration.billing_nullifier.into())
            .call()
            .await?
    );
    let capacity = contract
        .getPeriodCapacity(scope.rp_id.into_inner(), scope.period_start)
        .call()
        .await?;
    assert_eq!(capacity.registeredCount, U256::from(1u64));

    // A second registration of the same nullifier is rejected before it costs gas.
    let err = authenticator
        .submit_billing_registration(&registration)
        .await
        .expect_err("an already registered nullifier is rejected");
    let AuthenticatorError::GatewayError { status, body } = err else {
        bail!("unexpected error: {err}");
    };
    assert_eq!(status.as_u16(), 409);
    assert!(
        body.contains(&GatewayErrorCode::BillingNullifierAlreadyRegistered.to_string()),
        "{body}"
    );

    // The Proof of Embedding Similarity over a token billed to the registered nullifier.
    let public = EmbeddingSimilarityRequestInputs::from_request(
        &proof_request,
        credential.credential.issuer_version,
    )?;
    let billed = flamingo_result(
        &proof_request,
        thumbnail,
        challenge_hash,
        registration.billing_nullifier,
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
    let result = authenticator
        .generate_embedding_similarity_proof(
            &proof_request,
            &billed,
            &credential,
            &hashes_json,
            Some(&witness),
            None,
            None,
        )
        .await?;
    let item = result
        .proof_response
        .embedding_similarity
        .as_ref()
        .ok_or_else(|| eyre!("no embedding similarity item"))?;
    assert_eq!(item.signing_key_attestation, billed.signing_key_attestation);
    let artifacts = zk_artifact_source();
    verify_embedding_similarity_proof(&item.proof, &public, artifacts.as_ref())?;

    // The proof binds the RP's request: another challenge fails verification.
    let other_challenge = EmbeddingSimilarityRequestInputs {
        challenge_hash: image_hash(b"another frame"),
        ..public.clone()
    };
    assert!(
        verify_embedding_similarity_proof(&item.proof, &other_challenge, artifacts.as_ref())
            .is_err()
    );

    // An RP that is not billed: no billing nullifier and no witness.
    let unbilled = flamingo_result(
        &proof_request,
        thumbnail,
        challenge_hash,
        FieldElement::ZERO,
    )?;
    let result = authenticator
        .generate_embedding_similarity_proof(
            &proof_request,
            &unbilled,
            &credential,
            &hashes_json,
            None,
            None,
            None,
        )
        .await?;
    let item = result
        .proof_response
        .embedding_similarity
        .ok_or_else(|| eyre!("no embedding similarity item"))?;
    verify_embedding_similarity_proof(&item.proof, &public, artifacts.as_ref())?;

    gateway.shutdown().await.ok();
    Ok(())
}
