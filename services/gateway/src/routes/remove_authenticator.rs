//! Remove authenticator handler.

use crate::{request::IntoRequest, routes::middleware::RequestId, types::AppState};
use axum::{Extension, Json, extract::State};
use world_id_core::types::{
    GatewayErrorResponse, GatewayStatusResponse, RemoveAuthenticatorRequest,
};

/// POST /v1/authenticators/remove
///
/// Remove an authenticator from an account.
pub(crate) async fn remove_authenticator(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<RemoveAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
