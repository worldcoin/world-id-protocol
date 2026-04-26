//! Initiate recovery agent update handler.

use crate::{
    RegistryVersion,
    error::GatewayErrorResponse,
    request::{IntoRequestWithRateLimit, UpdateRecoveryAgentV2Request},
    routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::api_types::{GatewayStatusResponse, UpdateRecoveryAgentRequest};

/// POST /initiate-recovery-agent-update
///
/// Legacy URL. Pre-V2: initiates a time-locked recovery agent update (14-day
/// cooldown flow). Post-V2: translates into a WIP-102 `updateRecoveryAgent`.
///
/// TODO(WIP-102): remove this handler and its route once all clients have
/// migrated to `POST /update-recovery-agent`.
#[instrument(name = "initiate_recovery_agent_update", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn initiate_recovery_agent_update(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<UpdateRecoveryAgentRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    match state.ctx.registry_version {
        RegistryVersion::V1 => payload
            .into_request_with_rate_limit(id, &state.ctx)
            .await?
            .submit(&state.ctx)
            .await
            .map(|r| Json(r.into_response())),
        RegistryVersion::V2 => UpdateRecoveryAgentV2Request(payload)
            .into_request_with_rate_limit(id, &state.ctx)
            .await?
            .submit(&state.ctx)
            .await
            .map(|r| Json(r.into_response())),
    }
}
