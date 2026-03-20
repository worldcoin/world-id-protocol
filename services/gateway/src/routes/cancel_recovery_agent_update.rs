//! Cancel recovery agent update handler.

use crate::error::GatewayErrorResponse;
use axum::http::StatusCode;
use tracing::instrument;
use world_id_core::api_types::GatewayErrorCode;

/// POST /cancel-recovery-agent-update
///
/// Stub endpoint for cancelling a pending recovery agent update.
#[instrument(name = "cancel_recovery_agent_update")]
pub(crate) async fn cancel_recovery_agent_update() -> Result<(), GatewayErrorResponse> {
    Err(GatewayErrorResponse::new(
        GatewayErrorCode::InternalServerError,
        "cancel recovery agent update endpoint is not implemented yet".to_string(),
        StatusCode::NOT_IMPLEMENTED,
    ))
}
