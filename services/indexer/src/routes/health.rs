use crate::{api_error::IndexerErrorResponse, config::AppState};
use axum::{Json, extract::State};
use world_id_core::api_types::HealthResponse;

pub(crate) async fn handler(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, IndexerErrorResponse> {
    state.db.ping().await.map_err(|e| {
        tracing::error!("error pinging the database: {}", e);
        IndexerErrorResponse::internal_server_error()
    })?;

    Ok(Json(HealthResponse { success: true }))
}
