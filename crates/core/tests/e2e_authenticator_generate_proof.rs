#![cfg(feature = "authenticator")]

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{
    network::EthereumWallet, primitives::U256, providers::ProviderBuilder, sol_types::SolEvent,
};
use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use eyre::{eyre, Context as _, Result};
use k256::ecdsa::{
    signature::{Signer, Verifier},
    SigningKey, VerifyingKey,
};
use oprf_core::ddlog_equality::DLogEqualitySession;
use oprf_types::{
    api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse},
    crypto::{PartyId, RpNullifierKey},
    RpId, ShareEpoch,
};
use oprf_world_types::{api::v1::OprfRequestAuth, MerkleRoot};
use rand::{thread_rng, Rng};
use test_utils::{
    anvil::{CredentialSchemaIssuerRegistry, TestAnvil},
    merkle::first_leaf_merkle_path,
};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use world_id_core::{Authenticator, AuthenticatorError, EdDSAPrivateKey, HashableCredential};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig};
use world_id_primitives::{
    authenticator::AuthenticatorPublicKeySet,
    credential::Credential,
    merkle::{AccountInclusionProof, MerkleInclusionProof},
    Config, FieldElement, TREE_DEPTH,
};

const GW_PORT: u16 = 4104;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    // Spin up Anvil and deploy required contracts (AccountRegistry).
    let anvil = TestAnvil::spawn().wrap_err("failed to spawn anvil")?;
    let deployer = anvil
        .signer(0)
        .wrap_err("failed to fetch deployer signer for anvil")?;
    let registry_address = anvil
        .deploy_account_registry(deployer.clone())
        .await
        .wrap_err("failed to deploy account registry")?;

    // Step 2: Spawn the gateway wired to this Anvil instance.
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
    let key_set = AuthenticatorPublicKeySet::new(Some(vec![authenticator.offchain_pubkey()]))
        .wrap_err("failed to assemble key set")?;
    let leaf_commitment = Authenticator::leaf_hash(&key_set);
    let (siblings, root_field_element) = first_leaf_merkle_path(leaf_commitment);
    let merkle_proof = MerkleInclusionProof::new(root_field_element, account_id_u64, siblings);
    let inclusion_proof =
        AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_proof, key_set.clone())
            .wrap_err("failed to build inclusion proof")?;

    let (indexer_url, indexer_handle) = spawn_indexer_stub(account_id_u64, inclusion_proof.clone())
        .await
        .wrap_err("failed to start indexer stub")?;

    // Step 5a: Local OPRF peer stub setup.
    let merkle_root_fq: Fq = *root_field_element;
    let merkle_root = MerkleRoot::from(merkle_root_fq);
    let mut rng = thread_rng();
    let rp_signing_key = SigningKey::random(&mut rng);
    let rp_verifying_key = VerifyingKey::from(&rp_signing_key);
    let oprf_server = spawn_oprf_stub(merkle_root, rp_verifying_key)
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

    // Deploy CredentialSchemaIssuerRegistry and register issuer.
    let issuer_registry_address = anvil
        .deploy_credential_schema_issuer_registry(deployer.clone())
        .await
        .wrap_err("failed to deploy credential schema issuer registry")?;
    let issuer_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(deployer.clone()))
        .connect_http(
            anvil
                .endpoint()
                .parse()
                .wrap_err("invalid anvil endpoint URL")?,
        );
    let registry_contract =
        CredentialSchemaIssuerRegistry::new(issuer_registry_address, issuer_provider);

    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();
    let issuer_pubkey = CredentialSchemaIssuerRegistry::Pubkey {
        x: U256::from_limbs(issuer_pk.pk.x.into_bigint().0),
        y: U256::from_limbs(issuer_pk.pk.y.into_bigint().0),
    };
    let issuer_receipt = registry_contract
        .register(issuer_pubkey.clone(), deployer.address())
        .send()
        .await
        .wrap_err("failed to submit issuer registration transaction")?
        .get_receipt()
        .await
        .wrap_err("failed to fetch issuer registration receipt")?;
    let issuer_schema_id = issuer_receipt
        .logs()
        .iter()
        .find_map(|log| {
            CredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(log.inner.as_ref())
                .ok()
        })
        .expect("IssuerSchemaRegistered event not emitted")
        .issuerSchemaId;
    let issuer_schema_id_u64: u64 = issuer_schema_id
        .try_into()
        .expect("issuer schema id fits in u64");

    // Create and sign credential.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let mut credential = Credential::new()
        .issuer_schema_id(issuer_schema_id_u64)
        .account_id(account_id_u64)
        .genesis_issued_at(now)
        .expires_at(now + 86_400);
    credential.issuer = issuer_pk;
    let credential_hash = credential
        .hash()
        .wrap_err("failed to hash credential prior to signing")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    // Prepare RP request inputs.
    let action = Fq::rand(&mut rng);
    let nonce = Fq::rand(&mut rng);
    let signal_hash: FieldElement = FieldElement::from(Fq::rand(&mut rng));
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let mut rp_msg = Vec::new();
    rp_msg.extend(nonce.into_bigint().to_bytes_le());
    rp_msg.extend(current_timestamp.to_le_bytes());
    let rp_signature = rp_signing_key.sign(&rp_msg);

    let rp_request = world_id_core::types::RpRequest {
        rp_id: oprf_server.rp_id.into_inner().to_string(),
        rp_nullifier_key: oprf_server.rp_nullifier_key,
        signature: rp_signature,
        current_time_stamp: current_timestamp,
        action_id: action.into(),
        nonce: nonce.into(),
    };

    // Step 5b: Call generate_proof and ensure a nullifier is produced.
    let (_proof, nullifier) = authenticator
        .generate_proof(signal_hash, rp_request, credential)
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
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
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
) -> Result<OprfServerHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .wrap_err("failed to bind oprf stub listener")?;
    let addr: SocketAddr = listener
        .local_addr()
        .wrap_err("failed to read oprf stub address")?;

    let mut rng = thread_rng();
    let rp_secret = Fr::rand(&mut rng);
    let rp_public = (EdwardsAffine::generator() * rp_secret).into_affine();
    let state = Arc::new(OprfStubState {
        rp_secret,
        rp_public,
        rp_id: RpId::new(rng.gen()),
        share_epoch: ShareEpoch::default(),
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
        rp_id: state.rp_id,
        rp_nullifier_key: RpNullifierKey::new(state.rp_public),
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
