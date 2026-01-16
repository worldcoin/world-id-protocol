use crate::types::AppState;
use alloy::{primitives::U256, providers::DynProvider};
use axum::{extract::State, Json};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;
use world_id_core::{
    types::{GatewayErrorResponse, IsValidRootQuery, IsValidRootResponse},
    world_id_registry::WorldIdRegistry,
};
<<<<<<< HEAD
use alloy::primitives::U256;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
=======
>>>>>>> main

/// Default root validity window for LRU cache.
///
/// Set to 1 hour.
const DEFAULT_CACHE_TTL_SECS: u64 = 60 * 60;
/// Safety buffer for expirations, so we expire a bit early relative to chain time.
const CACHE_SKEW_SECS: u64 = 120;

/// Parse a hex string into a `U256`.
pub(crate) fn req_u256(_field: &str, s: &str) -> Result<U256, GatewayErrorResponse> {
    s.parse()
        .map_err(|e| GatewayErrorResponse::bad_request_message(format!("invalid value: {e}")))
}

/// Return the current timestamp in seconds since the UNIX_EPOCH.
fn now_timestamp() -> Result<U256, GatewayErrorResponse> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayErrorResponse::internal_server_error())?;
    Ok(U256::from(duration.as_secs()))
}

fn is_expired(expires_at: U256, now: U256) -> bool {
    expires_at <= now
}

/// Return a cached validity value when present and not expired.
fn get_cached_root(state: &AppState, root: U256, now: U256) -> bool {
    let mut cache = state.root_cache.lock();
    let expires_at = match cache.get(&root) {
        Some(ts) => *ts,
        None => return false,
    };
    if is_expired(expires_at, now) {
        // Expired entries are removed so future lookups fall through.
        cache.pop(&root);
        return false;
    }
    true
}

/// Cache decision for a valid root.
enum CachePolicy {
    Cache(U256),
    Skip,
}

/// Decide whether and for how long to cache a valid root.
async fn cache_policy_for_root(
    contract: &WorldIdRegistry::WorldIdRegistryInstance<DynProvider>,
    root: U256,
    now: U256,
) -> Result<CachePolicy, GatewayErrorResponse> {
    let ts = contract
        .rootToTimestamp(root)
        .call()
        .await
        .map_err(|e| GatewayErrorResponse::from_simulation_error(e.to_string()))?;
    if ts == U256::ZERO {
        // Unknown roots can become valid later; don't cache.
        return Ok(CachePolicy::Skip);
    }

    let validity_window = contract
        .rootValidityWindow()
        .call()
        .await
        .map_err(|e| GatewayErrorResponse::from_simulation_error(e.to_string()))?;
    if validity_window == U256::ZERO {
        // The WorldIdRegistry contract considers the root valid forever if
        // validity_window == 0, we set a default expiration to 1 hour in the future.
        return Ok(CachePolicy::Cache(now + U256::from(DEFAULT_CACHE_TTL_SECS)));
    }

    // Subtract a small skew allowance to avoid serving expired roots if local time lags chain time.
    let expiration = ts
        .saturating_add(validity_window)
        .saturating_sub(U256::from(CACHE_SKEW_SECS));
    if is_expired(expiration, now) {
        // Expired roots may still be valid if they are the latest root.
        return Ok(CachePolicy::Skip);
    }

    // Only cache valid roots until the on-chain expiration boundary.
    Ok(CachePolicy::Cache(expiration))
}

/// Validate whether a root is currently valid according to the registry contract.
pub(crate) async fn is_valid_root(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<IsValidRootQuery>,
) -> Result<Json<IsValidRootResponse>, GatewayErrorResponse> {
    let root = req_u256("root", &q.root)?;
<<<<<<< HEAD
    let valid = state
        .regsitry
=======
    let now = now_timestamp()?;
    if get_cached_root(&state, root, now) {
        return Ok(Json(IsValidRootResponse { valid: true }));
    }
    let contract = WorldIdRegistry::new(state.registry_addr, state.provider.clone());
    let valid = contract
>>>>>>> main
        .isValidRoot(root)
        .call()
        .await
        .map_err(|e| GatewayErrorResponse::from_simulation_error(e.to_string()))?;
    if valid {
        // Cache only valid roots to avoid serving stale negatives indefinitely.
        match cache_policy_for_root(&contract, root, now).await {
            Ok(CachePolicy::Cache(expires_at)) => {
                state.root_cache.lock().put(root, expires_at);
            }
            Ok(CachePolicy::Skip) => {}
            Err(err) => {
                warn!(
                    error = %err,
                    "root cache policy failed; skipping cache fill"
                );
            }
        }
    }
    Ok(Json(IsValidRootResponse { valid }))
}
