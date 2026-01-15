use axum::{response::IntoResponse, Json, Router};
use utoipa::OpenApi;
use world_id_core::types::{
    AccountInclusionProofSchema, IndexerErrorBody, IndexerPackedAccountRequest,
    IndexerPackedAccountResponse, IndexerQueryRequest, IndexerSignatureNonceResponse,
};

use crate::config::AppState;
mod get_packed_account;
mod get_signature_nonce;
mod health;
mod inclusion_proof;

#[derive(OpenApi)]
#[openapi(
    paths(
        get_packed_account::handler,
        get_signature_nonce::handler,
        inclusion_proof::handler,
    ),
    components(schemas(
        IndexerPackedAccountRequest,
        IndexerPackedAccountResponse,
        IndexerQueryRequest,
        IndexerSignatureNonceResponse,
        AccountInclusionProofSchema,
        IndexerErrorBody,
    )),
    tags(
        (name = "indexer", description = "World ID Indexer. Provides Merkle inclusion proofs and account information from the on-chain registry.")
    )
)]
struct ApiDoc;

async fn openapi() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

pub(crate) fn handler(state: AppState) -> Router {
    Router::new()
        .route(
            "/inclusion-proof",
            axum::routing::post(inclusion_proof::handler),
        )
        .route(
            "/packed-account",
            axum::routing::post(get_packed_account::handler),
        )
        .route(
            "/signature-nonce",
            axum::routing::post(get_signature_nonce::handler),
        )
        .route("/health", axum::routing::get(health::handler))
        .route("/openapi.json", axum::routing::get(openapi))
        .with_state(state)
}
