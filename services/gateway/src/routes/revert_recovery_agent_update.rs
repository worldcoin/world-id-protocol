//! Revert recovery agent update handler.

use crate::{
    error::GatewayErrorResponse,
    request::{IntoRequestWithRateLimit, RevertRecoveryAgentUpdateRequest},
    routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::api_types::{CancelRecoveryAgentUpdateRequest, GatewayStatusResponse};

/// POST /revert-recovery-agent-update
///
/// Revert an in-flight WIP-102 Recovery Agent update within the revert window.
/// Requires the registry proxy to be on the V2 implementation.
#[instrument(name = "revert_recovery_agent_update", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn revert_recovery_agent_update(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CancelRecoveryAgentUpdateRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    RevertRecoveryAgentUpdateRequest(payload)
        .into_request_with_rate_limit(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
