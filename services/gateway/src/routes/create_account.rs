//! Create account handler.

use crate::{request::IntoRequest, routes::middleware::RequestId, types::AppState};
use axum::{Extension, Json, extract::State};
use world_id_core::types::{CreateAccountRequest, GatewayErrorResponse, GatewayStatusResponse};

/// POST /v1/accounts
///
/// Create a new World ID account.
pub(crate) async fn create_account(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
