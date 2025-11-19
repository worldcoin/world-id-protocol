#![cfg(feature = "authenticator")]

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::primitives::U256;
use ark_babyjubjub::{EdwardsAffine, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use eyre::{eyre, Context as _, Result};
use k256::ecdsa::{signature::Verifier, VerifyingKey};
use oprf_core::ddlog_equality::DLogEqualitySession;
use oprf_types::{
    api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse},
    crypto::{PartyId, RpNullifierKey},
    RpId, ShareEpoch,
};
use oprf_world_types::{api::v1::OprfRequestAuth, MerkleRoot};
use rand::thread_rng;
use test_utils::fixtures::{
    build_base_credential, generate_rp_fixture, single_leaf_merkle_fixture, MerkleFixture,
    RegistryTestContext,
};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use uuid::Uuid;
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

    let mut rng = thread_rng();
    let rp_fixture = generate_rp_fixture(&mut rng);

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

#[derive(Clone)]
struct IndexerState {
    account_id: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
}

async fn spawn_indexer_stub(
    account_id: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
) -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .wrap_err("failed to bind indexer stub listener")?;
    let addr = listener
        .local_addr()
        .wrap_err("failed to read listener address")?;
    let state = IndexerState { account_id, proof };
    let handle = tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/proof/{account_id}",
                get(
                    |Path(requested): Path<u64>, State(state): State<IndexerState>| async move {
                        if requested != state.account_id {
                            return Err(StatusCode::NOT_FOUND);
                        }
                        Ok::<_, StatusCode>(Json(state.proof.clone()))
                    },
                ),
            )
            .with_state(state);
        axum::serve(listener, app)
            .await
            .expect("indexer stub server crashed");
    });

    Ok((format!("http://{addr}"), handle))
}

struct OprfServerHandle {
    base_url: String,
    join_handle: JoinHandle<()>,
}

struct OprfStubState {
    rp_secret: Fr,
    rp_public: EdwardsAffine,
    rp_id: RpId,
    share_epoch: ShareEpoch,
    party_id: PartyId,
    expected_root: MerkleRoot,
    verifier: VerifyingKey,
    sessions: Mutex<HashMap<Uuid, DLogEqualitySession>>,
}

async fn spawn_oprf_stub(
    expected_root: MerkleRoot,
    verifier: VerifyingKey,
    rp_id: RpId,
    share_epoch: ShareEpoch,
    rp_secret: Fr,
) -> Result<OprfServerHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .wrap_err("failed to bind oprf stub listener")?;
    let addr: SocketAddr = listener
        .local_addr()
        .wrap_err("failed to read oprf stub address")?;

    let rp_public = (EdwardsAffine::generator() * rp_secret).into_affine();
    let state = Arc::new(OprfStubState {
        rp_secret,
        rp_public,
        rp_id,
        share_epoch,
        party_id: PartyId::from(1u16),
        expected_root,
        verifier,
        sessions: Mutex::new(HashMap::new()),
    });

    let router_state = Arc::clone(&state);
    let app = Router::new()
        .route(
            "/api/v1/init",
            post({
                move |state: State<Arc<OprfStubState>>,
                      Json(req): Json<OprfRequest<OprfRequestAuth>>| {
                    oprf_init(state, req)
                }
            }),
        )
        .route(
            "/api/v1/finish",
            post({
                move |state: State<Arc<OprfStubState>>, Json(req): Json<ChallengeRequest>| {
                    oprf_finish(state, req)
                }
            }),
        )
        .with_state(router_state);

    let join_handle =
        tokio::spawn(async move { axum::serve(listener, app).await.expect("oprf stub crashed") });

    Ok(OprfServerHandle {
        base_url: format!("http://{addr}"),
        join_handle,
    })
}

async fn oprf_init(
    State(state): State<Arc<OprfStubState>>,
    req: OprfRequest<OprfRequestAuth>,
) -> Result<Json<OprfResponse>, StatusCode> {
    if req.blinded_query.is_zero()
        || req.rp_identifier.rp_id != state.rp_id
        || req.rp_identifier.share_epoch != state.share_epoch
        || req.auth.merkle_root != state.expected_root
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut msg = Vec::new();
    msg.extend(req.auth.nonce.into_bigint().to_bytes_le());
    msg.extend(req.auth.current_time_stamp.to_le_bytes());
    state
        .verifier
        .verify(&msg, &req.auth.signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let (session, commitments) = DLogEqualitySession::partial_commitments(
        req.blinded_query,
        state.rp_secret,
        &mut thread_rng(),
    );
    state.sessions.lock().await.insert(req.request_id, session);

    Ok(Json(OprfResponse {
        request_id: req.request_id,
        commitments,
        party_id: state.party_id,
    }))
}

async fn oprf_finish(
    State(state): State<Arc<OprfStubState>>,
    req: ChallengeRequest,
) -> Result<Json<ChallengeResponse>, StatusCode> {
    if req.rp_identifier.rp_id != state.rp_id || req.rp_identifier.share_epoch != state.share_epoch
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let session = state
        .sessions
        .lock()
        .await
        .remove(&req.request_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let parties = req.challenge.get_contributing_parties().to_vec();
    let proof_share = session.challenge(
        req.request_id,
        &parties,
        state.rp_secret,
        state.rp_public,
        req.challenge.clone(),
    );

    Ok(Json(ChallengeResponse {
        request_id: req.request_id,
        proof_share,
    }))
}
