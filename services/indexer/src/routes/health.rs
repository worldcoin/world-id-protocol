use axum::{extract::State, Json};
use serde::Serialize;
use sqlx::PgPool;

use crate::error::ErrorResponse;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    success: bool,
}

pub(crate) async fn handler(
    State(pool): State<PgPool>,
) -> Result<Json<HealthResponse>, ErrorResponse> {
    let count = sqlx::query("select count(*) from accounts limit 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            tracing::error!("error querying the database for accounts: {}", e);
            ErrorResponse::internal_server_error()
        })?;

    if count.is_none() {
        tracing::error!("error querying the database for accounts (empty result)");
        return Err(ErrorResponse::internal_server_error());
    }

    Ok(Json(HealthResponse { success: true }))
}
