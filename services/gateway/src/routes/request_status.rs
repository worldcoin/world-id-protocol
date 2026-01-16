use crate::request_tracker::RequestTracker;
use axum::{extract::Path, Json};
use world_id_core::types::{GatewayErrorResponse, GatewayStatusResponse};

pub(crate) async fn request_status(
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Path(id): Path<String>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let record = tracker
        .snapshot(&id)
        .await
        .ok_or_else(GatewayErrorResponse::not_found)?;

    let body = GatewayStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok(Json(body))
}
