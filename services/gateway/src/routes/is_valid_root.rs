use crate::{
    types::{ApiResult, AppState, RootCacheEntry},
    ErrorResponse as ApiError,
};
use alloy::primitives::U256;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
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

/// Return the current timestamp in seconds since the UNIX_EPOCH.
fn now_timestamp() -> ApiResult<U256> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal_server_error())?;
    Ok(U256::from(duration.as_secs()))
}

pub(crate) async fn is_valid_root(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<IsValidRootQuery>,
) -> ApiResult<impl IntoResponse> {
    let root = req_u256("root", &q.root)?;
    let now = now_timestamp()?;
    if let Some(entry) = {
        let mut cache = state.root_cache.lock();
        if let Some(entry) = cache.get(&root).cloned() {
            let fresh = entry.expires_at.map(|ts| ts > now).unwrap_or(true);
            if fresh {
                Some(entry)
            } else {
                cache.pop(&root);
                None
            }
        } else {
            None
        }
    } {
        return Ok((StatusCode::OK, Json(serde_json::json!({"valid": entry.valid}))));
    }
    let contract = WorldIdRegistry::new(state.registry_addr, state.provider.clone());
    let valid = contract
        .isValidRoot(root)
        .call()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if valid {
        let validity_window = contract
            .rootValidityWindow()
            .call()
            .await
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        let expires_at = if validity_window == U256::ZERO {
            None
        } else {
            let ts = contract
                .rootToTimestamp(root)
                .call()
                .await
                .map_err(|e| ApiError::bad_request(e.to_string()))?;
            if ts == U256::ZERO {
                None
            } else {
                let expiration = ts + validity_window;
                if expiration > now {
                    Some(expiration)
                } else {
                    None
                }
            }
        };
        state.root_cache.lock().put(
            root,
            RootCacheEntry {
                valid,
                expires_at,
            },
        );
    }
    Ok((StatusCode::OK, Json(serde_json::json!({"valid": valid}))))
}
