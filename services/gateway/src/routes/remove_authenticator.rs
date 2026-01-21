//! Remove authenticator handler.

use crate::request::IntoRequest;
use crate::routes::middleware::RequestId;
use crate::types::AppState;
use axum::{extract::State, Extension, Json};
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
        .into_request(id, &state.regsitry)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
