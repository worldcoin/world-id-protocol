use crate::{
    ops_batcher::{OpEnvelope, OpKind},
    request_tracker::RequestTracker,
    routes::validation::ValidateRequest,
    types::AppState,
};
use alloy::primitives::Bytes;
use axum::{extract::State, http::StatusCode, Json};
use world_id_core::{
    types::{
        GatewayErrorCode as ErrorCode, GatewayErrorResponse, GatewayRequestKind,
        GatewayRequestState, GatewayStatusResponse, UpdateAuthenticatorRequest,
    },
    world_id_registry::WorldIdRegistry,
};

pub(crate) async fn update_authenticator(
    State(state): State<AppState>,
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Json(req): Json<UpdateAuthenticatorRequest>,
) -> Result<(StatusCode, Json<GatewayStatusResponse>), GatewayErrorResponse> {
    // Input validation
    req.validate()?;

    // Simulate the operation before queueing to catch errors early
    let contract = WorldIdRegistry::new(state.registry_addr, state.provider.clone());
    contract
        .updateAuthenticator(
            req.leaf_index,
            req.old_authenticator_address,
            req.new_authenticator_address,
            req.pubkey_id,
            req.new_authenticator_pubkey,
            req.old_offchain_signer_commitment,
            req.new_offchain_signer_commitment,
            Bytes::from(req.signature.clone()),
            req.sibling_nodes.clone(),
            req.nonce,
        )
        .call()
        .await
        .map_err(GatewayErrorResponse::from_simulation_error)?;

    let (id, record) = tracker
        .new_request(GatewayRequestKind::UpdateAuthenticator)
        .await?;

    let env = OpEnvelope {
        id: id.clone(),
        kind: OpKind::Update {
            leaf_index: req.leaf_index,
            old_authenticator_address: req.old_authenticator_address,
            new_authenticator_address: req.new_authenticator_address,
            old_commit: req.old_offchain_signer_commitment,
            new_commit: req.new_offchain_signer_commitment,
            sibling_nodes: req.sibling_nodes.clone(),
            signature: Bytes::from(req.signature.clone()),
            nonce: req.nonce,
            pubkey_id: req.pubkey_id,
            new_pubkey: req.new_authenticator_pubkey,
        },
    };

    if state.ops_batcher.tx.send(env).await.is_err() {
        tracker
            .set_status(
                &id,
                GatewayRequestState::failed_from_code(ErrorCode::BatcherUnavailable),
            )
            .await;
        return Err(GatewayErrorResponse::batcher_unavailable());
    }

    let body = GatewayStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::ACCEPTED, Json(body)))
}
