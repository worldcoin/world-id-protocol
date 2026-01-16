use crate::config::AppState;
use axum::{extract::State, Json};
use world_id_core::types::{HealthResponse, IndexerErrorResponse};

pub(crate) async fn handler(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, IndexerErrorResponse> {
    let query = sqlx::query("select 1")
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("error querying the database for accounts: {}", e);
            IndexerErrorResponse::internal_server_error()
        })?;

    if query.is_none() {
        tracing::error!("error querying the database for accounts (empty result)");
        return Err(IndexerErrorResponse::internal_server_error());
    }

    Ok(Json(HealthResponse { success: true }))
}
