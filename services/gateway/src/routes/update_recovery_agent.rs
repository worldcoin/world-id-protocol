//! Update recovery agent handler.

use crate::{
    error::GatewayErrorResponse,
    request::{IntoRequestWithRateLimit, UpdateRecoveryAgentV2Request},
    routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_core::api_types::{GatewayStatusResponse, UpdateRecoveryAgentRequest};

/// POST /update-recovery-agent
///
/// Apply a WIP-102 optimistic Recovery Agent update. Requires the registry
/// proxy to be on the V2 implementation.
#[instrument(name = "update_recovery_agent", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn update_recovery_agent(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<UpdateRecoveryAgentRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    UpdateRecoveryAgentV2Request(payload)
        .into_request_with_rate_limit(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
