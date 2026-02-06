//! Request status handler.

use crate::types::AppState;
use axum::{
    Json,
    extract::{Path, State},
};
use tracing::instrument;
use world_id_core::api_types::{GatewayErrorResponse, GatewayStatusResponse};

/// GET /v1/requests/:id
///
/// Get the current status of a submitted request.
#[instrument(name = "request_status", skip(state), fields(request_id = %id))]
pub(crate) async fn request_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let record = state
        .ctx
        .tracker
        .snapshot(&id)
        .await
        .ok_or_else(GatewayErrorResponse::not_found)?;

    Ok(Json(GatewayStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    }))
}
