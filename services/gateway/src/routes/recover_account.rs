use crate::{
    ops_batcher::{OpEnvelope, OpKind},
    request_tracker::RequestTracker,
    routes::validation::ValidateRequest,
    types::AppState,
};
use alloy::primitives::{Bytes, U256};
use axum::{Json, extract::State, http::StatusCode};
use world_id_core::{
    types::{
        GatewayErrorCode as ErrorCode, GatewayErrorResponse, GatewayRequestKind,
        GatewayRequestState, GatewayStatusResponse, RecoverAccountRequest,
    },
    world_id_registry::WorldIdRegistry,
};

pub(crate) async fn recover_account(
    State(state): State<AppState>,
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Json(req): Json<RecoverAccountRequest>,
) -> Result<(StatusCode, Json<GatewayStatusResponse>), GatewayErrorResponse> {
    // Input validation
    req.validate()?;

    let new_pubkey = req.new_authenticator_pubkey.unwrap_or(U256::ZERO);
    // Simulate the operation before queueing to catch errors early
    let contract = WorldIdRegistry::new(state.registry_addr, state.provider.clone());
    contract
        .recoverAccount(
            req.leaf_index,
            req.new_authenticator_address,
            new_pubkey,
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
        .new_request(GatewayRequestKind::RecoverAccount)
        .await?;
    let env = OpEnvelope {
        id: id.clone(),
        kind: OpKind::Recover {
            leaf_index: req.leaf_index,
            new_authenticator_address: req.new_authenticator_address,
            old_commit: req.old_offchain_signer_commitment,
            new_commit: req.new_offchain_signer_commitment,
            sibling_nodes: req.sibling_nodes.clone(),
            signature: Bytes::from(req.signature.clone()),
            nonce: req.nonce,
            new_pubkey,
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
