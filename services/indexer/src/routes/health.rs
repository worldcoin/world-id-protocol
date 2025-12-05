use axum::{extract::State, Json};
use serde::Serialize;

use crate::{config::AppState, error::ErrorResponse};

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    success: bool,
}

pub(crate) async fn handler(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, ErrorResponse> {
    let query = sqlx::query("select 1")
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("error querying the database for accounts: {}", e);
            ErrorResponse::internal_server_error()
        })?;

    if query.is_none() {
        tracing::error!("error querying the database for accounts (empty result)");
        return Err(ErrorResponse::internal_server_error());
    }

    Ok(Json(HealthResponse { success: true }))
}
