use crate::{
    create_batcher::CreateReqEnvelope,
    request_tracker::{RequestKind, RequestState, RequestTracker},
    types::{ApiResult, AppState, RequestStatusResponse, MAX_AUTHENTICATORS},
    ErrorResponse as ApiError,
};
use alloy::{eips::eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS, primitives::Address};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use world_id_core::{
    types::{CreateAccountRequest, GatewayErrorCode as ErrorCode},
    world_id_registry::WorldIdRegistry,
};

pub(crate) async fn create_account(
    State(state): State<AppState>,
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Json(req): Json<CreateAccountRequest>,
) -> ApiResult<impl IntoResponse> {
    // Input validation
    if req.authenticator_addresses.len() > MAX_AUTHENTICATORS as usize {
        return Err(ApiError::bad_request(
            "authenticators cannot be more than {MAX_AUTHENTICATORS}".to_string(),
        ));
    }
    if req.authenticator_addresses.is_empty() {
        return Err(ApiError::bad_request(
            "authenticators cannot be empty".to_string(),
        ));
    }
    if req.authenticator_addresses.len() != req.authenticator_pubkeys.len() {
        return Err(ApiError::bad_request(
            "authenticators addresses must be equal to authenticators pubkeys".to_string(),
        ));
    }
    if req.authenticator_addresses.iter().any(|a| a.is_zero()) {
        return Err(ApiError::bad_request(
            "authenticator address cannot be zero".to_string(),
        ));
    }

    // Simulate the account creation before queueing to catch errors early
    let contract = WorldIdRegistry::new(state.registry_addr, state.provider.clone());
    contract
        .createAccount(
            req.recovery_address.unwrap_or(Address::ZERO),
            req.authenticator_addresses.clone(),
            req.authenticator_pubkeys.clone(),
            req.offchain_signer_commitment,
        )
        .call()
        .await
        .map_err(ApiError::from_simulation_error)?;

    let (id, record) = tracker.new_request(RequestKind::CreateAccount).await?;

    let env = CreateReqEnvelope {
        id: id.clone(),
        req,
    };

    if state.batcher.tx.send(env).await.is_err() {
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
