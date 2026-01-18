use crate::{
    batcher::{BackpressureError, OpEnvelopeInner, Operation, RemoveAuthenticatorOp},
    request_tracker::RequestTracker,
    routes::validation::ValidateRequest,
    types::AppState,
};
use alloy::primitives::{Bytes, U256};
use axum::{extract::State, Json};
use uuid::Uuid;
use world_id_core::types::{
    GatewayErrorCode as ErrorCode, GatewayErrorResponse, GatewayRequestKind, GatewayRequestState,
    GatewayStatusResponse, RemoveAuthenticatorRequest,
};

pub(crate) async fn remove_authenticator(
    State(state): State<AppState>,
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Json(req): Json<RemoveAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let pubkey_id = req.pubkey_id.unwrap_or(0);
    let authenticator_pubkey = req.authenticator_pubkey.unwrap_or(U256::ZERO);

    // Input validation
    req.validate()?;

    // Simulate the operation before queueing to catch errors early
    state
        .regsitry
        .removeAuthenticator(
            req.leaf_index,
            req.authenticator_address,
            pubkey_id,
            authenticator_pubkey,
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
        .new_request(GatewayRequestKind::RemoveAuthenticator)
        .await?;

    // Build the new operation envelope with all required fields
    let op = Operation::RemoveAuthenticator(RemoveAuthenticatorOp {
        leaf_index: req.leaf_index,
        authenticator_address: req.authenticator_address,
        pubkey_id,
        authenticator_pubkey,
        old_commit: req.old_offchain_signer_commitment,
        new_commit: req.new_offchain_signer_commitment,
        signature: Bytes::from(req.signature.clone()),
        sibling_nodes: req.sibling_nodes.clone(),
        nonce: req.nonce,
    });

    let env = OpEnvelopeInner::with_id(
        Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::new_v4()),
        op,
        req.authenticator_address,
        req.nonce,
    );

    if let Err(e) = state.ops_batcher.try_submit(env) {
        let error_code = match e {
            BackpressureError::QueueFull | BackpressureError::Timeout => {
                ErrorCode::BatcherUnavailable
            }
            BackpressureError::Shutdown => ErrorCode::BatcherUnavailable,
        };
        tracker
            .set_status(&id, GatewayRequestState::failed_from_code(error_code))
            .await;
        return Err(GatewayErrorResponse::batcher_unavailable());
    }

    let body = GatewayStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok(Json(body))
}
