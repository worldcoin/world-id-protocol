use crate::{
    types::{ApiResult, AppState, RootCacheEntry},
    ErrorResponse as ApiError,
};
use alloy::{primitives::U256, providers::DynProvider};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::{IntoParams, ToSchema};
use world_id_core::world_id_registry::WorldIdRegistry;

/// Query params for the `/is-valid-root` endpoint.
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub(crate) struct IsValidRootQuery {
    /// Root to validate (hex string).
    #[schema(value_type = String, format = "hex")]
    root: String,
}

/// Response payload for root validity checks.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct IsValidRootResponse {
    /// Whether the root is currently valid on-chain.
    valid: bool,
}

/// Parse a hex string into a `U256`.
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

/// Return a cached validity value when present and not expired.
fn get_cached_root(state: &AppState, root: U256, now: U256) -> Option<bool> {
    let mut cache = state.root_cache.lock();
    if let Some(entry) = cache.get(&root).cloned() {
        if entry.is_fresh(now) {
            return Some(entry.valid);
        }
        // Expired entries are removed so future lookups fall through.
        cache.pop(&root);
    }
    None
}

/// Compute the cache expiration time for a valid root.
async fn compute_root_expiration(
    contract: &WorldIdRegistry::WorldIdRegistryInstance<DynProvider>,
    root: U256,
    now: U256,
) -> ApiResult<Option<U256>> {
    let validity_window = contract
        .rootValidityWindow()
        .call()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if validity_window == U256::ZERO {
        return Ok(None);
    }

    let ts = contract
        .rootToTimestamp(root)
        .call()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if ts == U256::ZERO {
        return Ok(None);
    }

    // Only cache valid roots until the on-chain expiration boundary.
    let expiration = ts + validity_window;
    if expiration > now {
        Ok(Some(expiration))
    } else {
        Ok(None)
    }
}

/// Validate whether a root is currently valid according to the registry contract.
pub(crate) async fn is_valid_root(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<IsValidRootQuery>,
) -> ApiResult<impl IntoResponse> {
    let root = req_u256("root", &q.root)?;
    let now = now_timestamp()?;
    if let Some(valid) = get_cached_root(&state, root, now) {
        return Ok((StatusCode::OK, Json(serde_json::json!({"valid": valid}))));
    }
    let contract = WorldIdRegistry::new(state.registry_addr, state.provider.clone());
    let valid = contract
        .isValidRoot(root)
        .call()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if valid {
        // Cache only valid roots to avoid serving stale negatives indefinitely.
        let expires_at = compute_root_expiration(&contract, root, now).await?;
        state
            .root_cache
            .lock()
            .put(root, RootCacheEntry::new(valid, expires_at));
    }
    Ok((StatusCode::OK, Json(serde_json::json!({"valid": valid}))))
}
