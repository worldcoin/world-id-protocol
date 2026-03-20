//! Update recovery agent handler.

use crate::error::GatewayErrorResponse;
use axum::{Json, http::StatusCode};
use tracing::instrument;
use world_id_core::api_types::{GatewayErrorCode, UpdateRecoveryAgentRequest};

/// POST /update-recovery-agent
///
/// Stub endpoint for updating the recovery agent.
#[instrument(name = "update_recovery_agent", skip(_payload))]
pub(crate) async fn update_recovery_agent(
    Json(_payload): Json<UpdateRecoveryAgentRequest>,
) -> Result<(), GatewayErrorResponse> {
    Err(GatewayErrorResponse::new(
        GatewayErrorCode::InternalServerError,
        "update recovery agent endpoint is not implemented yet".to_string(),
        StatusCode::NOT_IMPLEMENTED,
    ))
}
