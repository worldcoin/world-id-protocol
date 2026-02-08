//! Insert authenticator handler.

use crate::{
    api_error::GatewayErrorResponse, request::IntoRequest, routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::api_types::{GatewayStatusResponse, InsertAuthenticatorRequest};

/// POST /v1/authenticators/insert
///
/// Insert a new authenticator to an existing account.
#[instrument(name = "insert_authenticator", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn insert_authenticator(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<InsertAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
