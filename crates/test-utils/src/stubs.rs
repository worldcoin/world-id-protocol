use std::{collections::HashMap, net::SocketAddr, sync::Arc};

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
use oprf_core::ddlog_equality::DLogEqualitySession;
use oprf_types::{
    api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse},
    crypto::PartyId,
    RpId, ShareEpoch,
};
use oprf_world_types::{api::v1::OprfRequestAuth, MerkleRoot};
use rand::thread_rng;
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use world_id_primitives::{merkle::AccountInclusionProof, TREE_DEPTH};

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
    rp_id: RpId,
    share_epoch: ShareEpoch,
    party_id: PartyId,
    expected_root: MerkleRoot,
    verifier: VerifyingKey,
    sessions: Mutex<HashMap<Uuid, DLogEqualitySession>>,
}

/// Spawns a local OPRF stub that validates RP metadata and drives the DLog equality flow.
pub async fn spawn_oprf_stub(
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
