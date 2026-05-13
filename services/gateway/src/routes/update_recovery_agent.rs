//! Update recovery agent handler.

use crate::{
    RegistryVersion,
    error::GatewayErrorResponse,
    request::{IntoRequestWithRateLimit, UpdateRecoveryAgentV2Request},
    routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State, http::StatusCode};
use tracing::instrument;
use world_id_primitives::api_types::{
    GatewayErrorCode, GatewayStatusResponse, UpdateRecoveryAgentRequest,
};

/// POST /update-recovery-agent
///
/// Apply a WIP-102 optimistic Recovery Agent update. Requires the registry
/// proxy to be on the V2 implementation; against V1 returns 501 Not Implemented.
#[instrument(name = "update_recovery_agent", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn update_recovery_agent(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<UpdateRecoveryAgentRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    if state.ctx.registry_version == RegistryVersion::V1 {
        return Err(GatewayErrorResponse::new(
            GatewayErrorCode::MethodNotAvailable,
            "POST /update-recovery-agent requires the registry to be on V2 (WIP-102). \
             The current registry is V1; use POST /initiate-recovery-agent-update instead."
                .to_string(),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    UpdateRecoveryAgentV2Request(payload)
        .into_request_with_rate_limit(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
