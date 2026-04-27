//! Revert recovery agent update handler.

use crate::{
    RegistryVersion,
    error::GatewayErrorResponse,
    request::{IntoRequestWithRateLimit, RevertRecoveryAgentUpdateRequest},
    routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State, http::StatusCode};
use tracing::instrument;
use world_id_primitives::api_types::{
    CancelRecoveryAgentUpdateRequest, GatewayErrorCode, GatewayStatusResponse,
};

/// POST /revert-recovery-agent-update
///
/// Revert an in-flight WIP-102 Recovery Agent update within the revert window.
/// Requires the registry proxy to be on the V2 implementation; against V1
/// returns 501 Not Implemented.
#[instrument(name = "revert_recovery_agent_update", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn revert_recovery_agent_update(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CancelRecoveryAgentUpdateRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    if state.ctx.registry_version == RegistryVersion::V1 {
        return Err(GatewayErrorResponse::new(
            GatewayErrorCode::MethodNotAvailable,
            "POST /revert-recovery-agent-update requires the registry to be on V2 (WIP-102). \
             The current registry is V1; use POST /cancel-recovery-agent-update instead."
                .to_string(),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    RevertRecoveryAgentUpdateRequest(payload)
        .into_request_with_rate_limit(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
