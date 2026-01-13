use crate::{
    ops_batcher::{OpEnvelope, OpKind},
    request_tracker::{RequestKind, RequestState, RequestTracker},
    types::{ApiResult, AppState, RequestStatusResponse, MAX_AUTHENTICATORS},
    ErrorResponse as ApiError,
};
use alloy::primitives::Bytes;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use world_id_core::{
    types::{GatewayErrorCode as ErrorCode, UpdateAuthenticatorRequest},
    world_id_registry::WorldIdRegistry,
};

pub(crate) async fn update_authenticator(
    State(state): State<AppState>,
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Json(req): Json<UpdateAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    if req.leaf_index.is_zero() {
        return Err(ApiError::bad_request(
            "leaf_index cannot be zero".to_string(),
        ));
    }
    if req.pubkey_id >= MAX_AUTHENTICATORS {
        return Err(ApiError::bad_request(format!(
            "pubkey_id must be less than {MAX_AUTHENTICATORS}"
        )));
    }
    if req.new_authenticator_address.is_zero() {
        return Err(ApiError::bad_request(
            "new_authenticator_address cannot be zero".to_string(),
        ));
    }

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
        .map_err(ApiError::from_simulation_error)?;

    let (id, record) = tracker
        .new_request(RequestKind::UpdateAuthenticator)
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
                RequestState::failed_from_code(ErrorCode::BatcherUnavailable),
            )
            .await;
        return Err(ApiError::batcher_unavailable());
    }

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::ACCEPTED, Json(body)))
}
