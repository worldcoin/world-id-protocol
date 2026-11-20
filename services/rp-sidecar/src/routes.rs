//! The HTTP routes.

use std::{num::NonZeroUsize, sync::Arc};

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    middleware::from_fn,
    routing::{get, post},
};
use world_id_primitives::api_types::HealthResponse;
use world_id_rp::embedding_similarity::FlamingoAttestationVerifier;

use crate::{registries::Registries, server::AppState};

mod embedding_similarity;

/// The sidecar's routes:
///
/// - `POST /v1/embedding-similarity/verify` verifies a Proof of Embedding Similarity.
/// - `GET /health` answers once the sidecar serves. It checks no dependency: a registry outage
///   answers verifications `503` instead, so it does not take the caller's pod out of service.
///
/// Bodies larger than `max_body_bytes` are answered `413 body_too_large`.
pub fn router<A, R>(state: AppState<A, R>, max_body_bytes: NonZeroUsize) -> Router
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
        .layer(DefaultBodyLimit::max(max_body_bytes.get()))
        .layer(from_fn(
            world_id_services_common::request_latency_middleware,
        ))
        .layer(world_id_services_common::trace_layer())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { success: true })
}
