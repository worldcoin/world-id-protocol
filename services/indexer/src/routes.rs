use axum::{response::IntoResponse, Json, Router};
use utoipa::OpenApi;

use crate::config::AppState;
use crate::error::ErrorObject;

mod get_packed_account;
mod get_signature_nonce;
mod health;
mod inclusion_proof;

#[derive(OpenApi)]
#[openapi(
    paths(
        get_packed_account::handler,
        get_signature_nonce::handler,
    ),
    components(schemas(
        get_packed_account::PackedAccountRequest,
        get_packed_account::PackedAccountResponse,
        get_signature_nonce::SignatureNonceRequest,
        get_signature_nonce::SignatureNonceResponse,
        ErrorObject,
    )),
    tags(
        (name = "indexer", description = "World ID Indexer. Provides Merkle inclusion proofs and packed account indices from the on-chain registry.")
    )
)]
struct ApiDoc;

async fn openapi() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

pub(crate) fn handler(state: AppState) -> Router {
    Router::new()
        .route(
            "/proof/:account_index",
            axum::routing::get(inclusion_proof::handler),
        )
        .route(
            "/packed_account",
            axum::routing::post(get_packed_account::handler),
        )
        .route(
            "/signature_nonce",
            axum::routing::post(get_signature_nonce::handler),
        )
        .route("/health", axum::routing::get(health::handler))
        .route("/openapi.json", axum::routing::get(openapi))
        .with_state(state)
}
