use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::Address;
use ark_babyjubjub::{EdwardsAffine, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use eyre::{Context as _, Result};
use k256::ecdsa::{signature::Verifier, VerifyingKey};
use oprf_core::{
    ddlog_equality::shamir::{DLogSessionShamir, DLogShareShamir},
    shamir,
};
use oprf_types::{
    api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse},
    crypto::PartyId,
    OprfKeyId, ShareEpoch,
};
use rand::thread_rng;
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use world_id_oprf_node::config::WorldOprfNodeConfig;
use world_id_primitives::{
    merkle::AccountInclusionProof, oprf::OprfRequestAuthV1, FieldElement, TREE_DEPTH,
};

use crate::test_secret_manager::TestSecretManager;

#[derive(Clone)]
struct IndexerState {
    account_id: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
}

/// Spawns a minimal HTTP server that serves the provided inclusion proof.
pub async fn spawn_indexer_stub(
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

pub struct OprfServerHandle {
    pub base_url: String,
    pub join_handle: JoinHandle<()>,
}

struct OprfStubState {
    rp_secret: Fr,
    rp_public: EdwardsAffine,
    rp_id: OprfKeyId,
    share_epoch: ShareEpoch,
    party_id: PartyId,
    expected_root: FieldElement,
    verifier: VerifyingKey,
    sessions: Mutex<HashMap<Uuid, DLogSessionShamir>>,
}

/// Spawns a local OPRF stub that validates RP metadata and drives the DLog equality flow.
pub async fn spawn_oprf_stub(
    expected_root: FieldElement,
    verifier: VerifyingKey,
    rp_id: OprfKeyId,
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
                      Json(req): Json<OprfRequest<OprfRequestAuthV1>>| {
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
    req: OprfRequest<OprfRequestAuthV1>,
) -> Result<Json<OprfResponse>, StatusCode> {
    if req.blinded_query.is_zero()
        || req.share_identifier.oprf_key_id != state.rp_id
        || req.share_identifier.share_epoch != state.share_epoch
        || req.auth.merkle_root != *state.expected_root
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

    let share = DLogShareShamir::from(state.rp_secret);
    let (session, commitments) =
        DLogSessionShamir::partial_commitments(req.blinded_query, share, &mut thread_rng());
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
    if req.share_identifier.oprf_key_id != state.rp_id
        || req.share_identifier.share_epoch != state.share_epoch
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let session = state
        .sessions
        .lock()
        .await
        .remove(&req.request_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let contributing_parties = req.challenge.get_contributing_parties().to_vec();
    let lagrange = shamir::single_lagrange_from_coeff::<Fr, u16>(
        state.party_id.into_inner() + 1,
        &contributing_parties,
    );
    let share = DLogShareShamir::from(state.rp_secret);
    let proof_share = session.challenge(
        req.request_id,
        share,
        state.rp_public,
        req.challenge.clone(),
        lagrange,
    );

    Ok(Json(ChallengeResponse {
        request_id: req.request_id,
        proof_share,
    }))
}

async fn spawn_orpf_node(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
    account_registry_contract: Address,
) -> String {
    let dir = PathBuf::from("/home/gruber/Work/nullifier-oracle-service/oprf-service");
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = WorldOprfNodeConfig {
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        max_wait_time_shutdown: Duration::from_secs(10),
        user_verification_key_path: dir.join("../circom/main/query/OPRFQuery.vk.json"),
        max_merkle_store_size: 10,
        current_time_stamp_max_difference: Duration::from_secs(10),
        signature_history_cleanup_interval: Duration::from_secs(30),
        account_registry_contract,
        node_config: oprf_service::config::OprfNodeConfig {
            environment: oprf_service::config::Environment::Dev,
            request_lifetime: Duration::from_secs(5 * 60),
            session_cleanup_interval: Duration::from_micros(1000000),
            rp_secret_id_prefix: format!("oprf/rp/n{id}"),
            oprf_key_registry_contract: rp_registry_contract,
            chain_ws_rpc_url: chain_ws_rpc_url.into(),
            key_gen_witness_graph_path: dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin"),
            key_gen_zkey_path: dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey"),
            wallet_private_key_secret_id: "wallet/privatekey".to_string(),
        },
    };
    let never = async { futures::future::pending::<()>().await };

    tokio::spawn(async move {
        let res = world_id_oprf_node::start(config, Arc::new(secret_manager), never).await;
        eprintln!("service failed to start: {res:?}");
    });
    // very graceful timeout for CI
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("can start");
    url
}

pub async fn spawn_oprf_nodes(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
    account_registry_contract: Address,
) -> [String; 3] {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    [
        spawn_orpf_node(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        spawn_orpf_node(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        spawn_orpf_node(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
    ]
}
