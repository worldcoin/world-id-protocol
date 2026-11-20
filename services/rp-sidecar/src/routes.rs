//! The HTTP routes.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    middleware::from_fn,
    routing::{get, post},
};
use world_id_primitives::api_types::HealthResponse;
use world_id_rp::embedding_similarity::FlamingoAttestationVerifier;

use crate::{error::ApiError, registries::Registries, server::AppState};

mod embedding_similarity;

/// The sidecar's routes:
///
/// - `POST /v1/embedding-similarity/verify` verifies a Proof of Embedding Similarity.
/// - `GET /health` answers once the sidecar serves. It checks no dependency: a registry outage
///   answers verifications `503` instead, so it does not take the caller's pod out of service.
///
/// Requests longer than `request_timeout_secs` are answered `503 timeout`, and bodies larger
/// than `max_body_bytes` `413 body_too_large`.
pub fn router<A, R>(
    state: AppState<A, R>,
    request_timeout_secs: u64,
    max_body_bytes: usize,
) -> Router
where
    A: FlamingoAttestationVerifier + Send + Sync + 'static,
    R: Registries,
{
    Router::new()
        .route(
            "/v1/embedding-similarity/verify",
            post(embedding_similarity::verify::<A, R>),
        )
        .route("/health", get(health))
        .with_state(Arc::new(state))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(from_fn(
            world_id_services_common::request_latency_middleware,
        ))
        .layer(world_id_services_common::timeout_layer(
            request_timeout_secs,
            ApiError::timeout(request_timeout_secs),
        ))
        .layer(world_id_services_common::trace_layer())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { success: true })
}
