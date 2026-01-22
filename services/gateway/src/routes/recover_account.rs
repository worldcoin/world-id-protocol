//! Recover account handler.

use crate::{request::IntoRequest, routes::middleware::RequestId, types::AppState};
use axum::{Extension, Json, extract::State};
use world_id_core::types::{GatewayErrorResponse, GatewayStatusResponse, RecoverAccountRequest};

/// POST /v1/accounts/recover
///
/// Recover an account using the recovery address.
pub(crate) async fn recover_account(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<RecoverAccountRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.regsitry)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
