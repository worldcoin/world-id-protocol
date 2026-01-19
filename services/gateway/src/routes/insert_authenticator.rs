use crate::{
    batcher::{InsertAuthenticatorOp, OpEnvelopeInner, Operation},
    routes::middleware::Validated,
    types::AppState,
};
use alloy::primitives::Bytes;
use axum::{extract::State, Json};
use uuid::Uuid;
use world_id_core::types::{
    GatewayErrorResponse, GatewayRequestKind, GatewayRequestState, GatewayStatusResponse,
    InsertAuthenticatorRequest,
};

pub(crate) async fn insert_authenticator(
    State(state): State<AppState>,
    Validated(req): Validated<InsertAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let id = Uuid::new_v4();
    let kind = GatewayRequestKind::InsertAuthenticator;

    // Build the operation envelope
    let op = Operation::InsertAuthenticator(InsertAuthenticatorOp {
        leaf_index: req.leaf_index,
        new_authenticator_address: req.new_authenticator_address,
        pubkey_id: req.pubkey_id,
        new_authenticator_pubkey: req.new_authenticator_pubkey,
        old_commit: req.old_offchain_signer_commitment,
        new_commit: req.new_offchain_signer_commitment,
        signature: Bytes::from(req.signature.clone()),
        sibling_nodes: req.sibling_nodes.clone(),
        nonce: req.nonce,
    });

    let env = OpEnvelopeInner::with_id(id, op, req.new_authenticator_address, req.nonce);

    // Submit and wait for tracking entry to be created
    let _result_rx = state
        .event_bus
        .submit_and_wait(env)
        .await
        .map_err(|_| GatewayErrorResponse::batcher_unavailable())?;

    Ok(Json(GatewayStatusResponse {
        request_id: id.to_string(),
        kind,
        status: GatewayRequestState::Queued,
    }))
}
