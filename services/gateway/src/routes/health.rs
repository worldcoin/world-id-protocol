use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HealthResponse {
    pub(crate) status: String,
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "General status check for the server", body = HealthResponse)
    ),
    tag = "Gateway"
)]
pub(crate) async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}
