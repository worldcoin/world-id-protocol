//! Update authenticator handler.

use crate::{request::IntoRequest, routes::middleware::RequestId, types::AppState};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::types::{
    GatewayErrorResponse, GatewayStatusResponse, UpdateAuthenticatorRequest,
};

/// POST /v1/authenticators/update
///
/// Update an existing authenticator.
#[instrument(name = "update_authenticator", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn update_authenticator(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<UpdateAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
