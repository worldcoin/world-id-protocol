//! Recover account handler.

use crate::{request::IntoRequest, routes::middleware::RequestId, types::AppState};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::types::{GatewayErrorResponse, GatewayStatusResponse, RecoverAccountRequest};

/// POST /v1/accounts/recover
///
/// Recover an account using the recovery address.
#[instrument(name = "recover_account", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn recover_account(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<RecoverAccountRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
