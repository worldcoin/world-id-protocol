use crate::{
    batcher::{OpEnvelopeInner, Operation, RemoveAuthenticatorOp},
    routes::middleware::Validated,
    types::AppState,
};
use alloy::primitives::{Bytes, U256};
use axum::{extract::State, Json};
use uuid::Uuid;
use world_id_core::types::{
    GatewayErrorResponse, GatewayRequestKind, GatewayRequestState, GatewayStatusResponse,
    RemoveAuthenticatorRequest,
};

pub(crate) async fn remove_authenticator(
    State(state): State<AppState>,
    Validated(req): Validated<RemoveAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let pubkey_id = req.pubkey_id.unwrap_or(0);
    let authenticator_pubkey = req.authenticator_pubkey.unwrap_or(U256::ZERO);
    let id = Uuid::new_v4();
    let kind = GatewayRequestKind::RemoveAuthenticator;

    // Build the operation envelope
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

    let env = OpEnvelopeInner::with_id(id, op, req.authenticator_address, req.nonce);

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
