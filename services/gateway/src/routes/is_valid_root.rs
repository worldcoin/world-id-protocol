use crate::{
    api_error::GatewayErrorResponse,
    metrics::{METRICS_ROOT_CACHE_HITS, METRICS_ROOT_CACHE_MISSES},
    request::Registry,
    types::AppState,
};
use alloy::primitives::U256;
use axum::{Json, extract::State};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{instrument, warn};
use world_id_core::api_types::{IsValidRootQuery, IsValidRootResponse};

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

/// Check if a root is present in the cache.
///
/// Expiration is handled automatically by moka's `Expiry` policy.
async fn is_cached_root(state: &AppState, root: U256) -> bool {
    state.ctx.root_cache.get(&root).await.is_some()
}

/// Cache decision for a valid root.
enum CachePolicy {
    Cache(U256),
    Skip,
}

/// Decide whether and for how long to cache a valid root.
async fn cache_policy_for_root(
    contract: Arc<Registry>,
    root: U256,
    now: U256,
) -> Result<CachePolicy, GatewayErrorResponse> {
    let ts = contract
        .getRootTimestamp(root)
        .call()
        .await
        .map_err(|e| GatewayErrorResponse::from_simulation_error(e.to_string()))?;
    if ts == U256::ZERO {
        // Unknown roots can become valid later; don't cache.
        return Ok(CachePolicy::Skip);
    }

    let validity_window = contract
        .getRootValidityWindow()
        .call()
        .await
        .map_err(|e| GatewayErrorResponse::from_simulation_error(e.to_string()))?;

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
#[instrument(name = "is_valid_root", skip(state), fields(root = %q.root))]
pub(crate) async fn is_valid_root(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<IsValidRootQuery>,
) -> Result<Json<IsValidRootResponse>, GatewayErrorResponse> {
    let root = req_u256("root", &q.root)?;
    if is_cached_root(&state, root).await {
        ::metrics::counter!(METRICS_ROOT_CACHE_HITS).increment(1);
        return Ok(Json(IsValidRootResponse { valid: true }));
    }
    ::metrics::counter!(METRICS_ROOT_CACHE_MISSES).increment(1);
    let now = now_timestamp()?;

    let valid = state
        .ctx
        .registry
        .isValidRoot(root)
        .call()
        .await
        .map_err(|e| GatewayErrorResponse::from_simulation_error(e.to_string()))?;
    if valid {
        // Cache only valid roots to avoid serving stale negatives indefinitely.
        match cache_policy_for_root(state.ctx.registry.clone(), root, now).await {
            Ok(CachePolicy::Cache(expires_at)) => {
                state.ctx.root_cache.insert(root, expires_at).await;
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
