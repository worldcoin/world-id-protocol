//! Cancel recovery agent update handler.

use crate::{
    error::GatewayErrorResponse, request::IntoRequestWithRateLimit, routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::api_types::{CancelRecoveryAgentUpdateRequest, GatewayStatusResponse};

/// POST /cancel-recovery-agent-update
///
/// Cancels a pending recovery agent update.
#[instrument(name = "cancel_recovery_agent_update", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn cancel_recovery_agent_update(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CancelRecoveryAgentUpdateRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request_with_rate_limit(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
