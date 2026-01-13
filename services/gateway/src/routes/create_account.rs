use crate::{
    create_batcher::CreateReqEnvelope,
    request_tracker::{RequestKind, RequestState, RequestTracker},
    types::{ApiResult, AppState, RequestStatusResponse},
    ErrorResponse as ApiError,
};
use alloy::primitives::Address;
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
