//! Execute recovery agent update handler.

use crate::{
    RegistryVersion, error::GatewayErrorResponse, request::IntoRequestWithRateLimit,
    routes::middleware::RequestId, types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::api_types::{
    ExecuteRecoveryAgentUpdateRequest, GatewayRequestId, GatewayRequestKind, GatewayRequestState,
    GatewayStatusResponse,
};

/// POST /execute-recovery-agent-update
///
/// Legacy URL. Pre-V2: executes a pending recovery agent update (permissionless;
/// the contract enforces the 14-day cooldown). Post-V2: no-op — WIP-102 applies
/// updates immediately, nothing to execute.
#[instrument(name = "execute_recovery_agent_update", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn execute_recovery_agent_update(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<ExecuteRecoveryAgentUpdateRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    match state.ctx.registry_version {
        RegistryVersion::V1 => payload
            .into_request_with_rate_limit(id, &state.ctx)
            .await?
            .submit(&state.ctx)
            .await
            .map(|r| Json(r.into_response())),
        RegistryVersion::V2 => {
            let _ = payload;
            Ok(Json(GatewayStatusResponse {
                request_id: GatewayRequestId::new(id.to_string()),
                kind: GatewayRequestKind::ExecuteRecoveryAgentUpdate,
                status: GatewayRequestState::Queued,
            }))
        }
    }
}
