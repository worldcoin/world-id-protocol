use axum::Json;
use world_id_core::api_types::HealthResponse;

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "General status check for the server", body = HealthResponse)
    ),
    tag = "Gateway"
)]
pub(crate) async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { success: true })
}
