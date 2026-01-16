use crate::{
    create_batcher::CreateReqEnvelope, request_tracker::RequestTracker,
    routes::validation::ValidateRequest, types::AppState,
};
use alloy::primitives::Address;
use axum::{extract::State, http::StatusCode, Json};
use world_id_core::types::{
    CreateAccountRequest, GatewayErrorCode as ErrorCode, GatewayErrorResponse, GatewayRequestKind,
    GatewayRequestState, GatewayStatusResponse,
};

pub(crate) async fn create_account(
    State(state): State<AppState>,
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<GatewayStatusResponse>), GatewayErrorResponse> {
    // Input validation
    req.validate()?;

    // Simulate the account creation before queueing to catch errors early
    state
        .regsitry
        .createAccount(
            req.recovery_address.unwrap_or(Address::ZERO),
            req.authenticator_addresses.clone(),
            req.authenticator_pubkeys.clone(),
            req.offchain_signer_commitment,
        )
        .call()
        .await
        .map_err(GatewayErrorResponse::from_simulation_error)?;

    let (id, record) = tracker
        .new_request(GatewayRequestKind::CreateAccount)
        .await?;

    let env = CreateReqEnvelope {
        id: id.clone(),
        req,
    };

    if state.batcher.tx.send(env).await.is_err() {
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
