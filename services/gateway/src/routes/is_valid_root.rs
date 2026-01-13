use crate::{
    types::{ApiResult, AppState},
    ErrorResponse as ApiError,
};
use alloy::primitives::U256;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use world_id_core::world_id_registry::WorldIdRegistry;

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub(crate) struct IsValidRootQuery {
    #[schema(value_type = String, format = "hex")]
    root: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct IsValidRootResponse {
    valid: bool,
}

pub(crate) fn req_u256(_field: &str, s: &str) -> ApiResult<U256> {
    s.parse()
        .map_err(|e| ApiError::bad_request(format!("invalid value: {}", e)))
}

pub(crate) async fn is_valid_root(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<IsValidRootQuery>,
) -> ApiResult<impl IntoResponse> {
    let root = req_u256("root", &q.root)?;
    let contract = WorldIdRegistry::new(state.registry_addr, state.provider.clone());
    let valid = contract
        .isValidRoot(root)
        .call()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok((StatusCode::OK, Json(serde_json::json!({"valid": valid}))))
}
