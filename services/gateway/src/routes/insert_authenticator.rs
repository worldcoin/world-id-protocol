//! Insert authenticator handler.

use crate::request::IntoRequest;
use crate::routes::middleware::RequestId;
use crate::types::AppState;
use axum::{extract::State, Extension, Json};
use world_id_core::types::{
    GatewayErrorResponse, GatewayStatusResponse, InsertAuthenticatorRequest,
};

/// POST /v1/authenticators/insert
///
/// Insert a new authenticator to an existing account.
pub(crate) async fn insert_authenticator(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<InsertAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.regsitry)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
