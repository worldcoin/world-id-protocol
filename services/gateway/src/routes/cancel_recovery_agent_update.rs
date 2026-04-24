//! Cancel recovery agent update handler.

use crate::{
    RegistryVersion,
    error::GatewayErrorResponse,
    request::{IntoRequestWithRateLimit, RevertRecoveryAgentUpdateRequest},
    routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::api_types::{CancelRecoveryAgentUpdateRequest, GatewayStatusResponse};

/// POST /cancel-recovery-agent-update
///
/// Legacy URL. Pre-V2: cancels a pending recovery agent update. Post-V2:
/// translates into a WIP-102 `revertRecoveryAgentUpdate`.
#[instrument(name = "cancel_recovery_agent_update", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn cancel_recovery_agent_update(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CancelRecoveryAgentUpdateRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    match state.ctx.registry_version {
        RegistryVersion::V1 => payload
            .into_request_with_rate_limit(id, &state.ctx)
            .await?
            .submit(&state.ctx)
            .await
            .map(|r| Json(r.into_response())),
        RegistryVersion::V2 => RevertRecoveryAgentUpdateRequest(payload)
            .into_request_with_rate_limit(id, &state.ctx)
            .await?
            .submit(&state.ctx)
            .await
            .map(|r| Json(r.into_response())),
    }
}
