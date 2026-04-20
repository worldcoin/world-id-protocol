//! Execute recovery agent update handler.

use crate::{
    error::GatewayErrorResponse, request::IntoRequestWithRateLimit, routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_primitives::api_types::{ExecuteRecoveryAgentUpdateRequest, GatewayStatusResponse};

/// POST /execute-recovery-agent-update
///
/// Executes a pending recovery agent update once the 14-day cooldown has elapsed.
///
/// This call is **permissionless** — no signature or nonce is required. The
/// contract enforces the cooldown and will revert with
/// `RecoveryAgentUpdateStillInCooldown` if called too early; that revert is
/// surfaced to the caller via the pre-flight `eth_call` simulation.
#[instrument(name = "execute_recovery_agent_update", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn execute_recovery_agent_update(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<ExecuteRecoveryAgentUpdateRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request_with_rate_limit(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
