use crate::error::{IndexerErrorBody, IndexerErrorResponse};
use alloy::primitives::Address;
use axum::{Json, Router, middleware::from_fn, response::IntoResponse};
use serde::Deserialize;
use utoipa::OpenApi;
use world_id_core::api_types::{
    AccountInclusionProofSchema, IndexerAuthenticatorPubkeysResponse, IndexerPackedAccountRequest,
    IndexerPackedAccountResponse, IndexerQueryRequest, IndexerRecoveryAgentResponse,
    IndexerSignatureNonceResponse,
};
use world_id_primitives::serde_utils::hex_u64;

use crate::config::AppState;
mod get_authenticator_pubkeys;
mod get_packed_account;
mod get_recovery_agent;
mod get_signature_nonce;
mod health;
mod inclusion_proof;
mod middleware;

#[derive(Debug, Deserialize)]
pub(crate) struct LeafIndexPath {
    #[serde(with = "hex_u64")]
    pub(crate) leaf_index: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthenticatorAddressPath {
    pub(crate) authenticator_address: Address,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_authenticator_pubkeys::handler,
        get_authenticator_pubkeys::v2_handler,
        get_packed_account::handler,
        get_packed_account::v2_handler,
        get_signature_nonce::handler,
        get_signature_nonce::v2_handler,
        get_recovery_agent::handler,
        get_recovery_agent::v2_handler,
        inclusion_proof::handler,
        inclusion_proof::v2_handler,
    ),
    components(schemas(
        IndexerAuthenticatorPubkeysResponse,
        IndexerPackedAccountRequest,
        IndexerPackedAccountResponse,
        IndexerQueryRequest,
        IndexerSignatureNonceResponse,
        IndexerRecoveryAgentResponse,
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

pub(crate) fn handler(state: AppState, request_timeout_secs: u64) -> Router {
    Router::new()
        .route(
            "/inclusion-proof",
            axum::routing::post(inclusion_proof::handler),
        )
        .route(
            "/authenticator-pubkeys",
            axum::routing::post(get_authenticator_pubkeys::handler),
        )
        .route(
            "/packed-account",
            axum::routing::post(get_packed_account::handler),
        )
        .route(
            "/signature-nonce",
            axum::routing::post(get_signature_nonce::handler),
        )
        .route(
            "/recovery-agent",
            axum::routing::post(get_recovery_agent::handler),
        )
        .route(
            "/v2/accounts/{leaf_index}/inclusion-proof",
            axum::routing::get(inclusion_proof::v2_handler),
        )
        .route(
            "/v2/accounts/{leaf_index}/authenticator-pubkeys",
            axum::routing::get(get_authenticator_pubkeys::v2_handler),
        )
        .route(
            "/v2/accounts/{leaf_index}/signature-nonce",
            axum::routing::get(get_signature_nonce::v2_handler),
        )
        .route(
            "/v2/accounts/{leaf_index}/recovery-agent",
            axum::routing::get(get_recovery_agent::v2_handler),
        )
        .route(
            "/v2/authenticators/{authenticator_address}/packed-account",
            axum::routing::get(get_packed_account::v2_handler),
        )
        .route("/health", axum::routing::get(health::handler))
        .route("/openapi.json", axum::routing::get(openapi))
        .with_state(state)
        .layer(from_fn(middleware::request_latency_middleware))
        .layer(world_id_services_common::timeout_layer(
            request_timeout_secs,
            IndexerErrorResponse::request_timeout(request_timeout_secs),
        ))
        .layer(world_id_services_common::trace_layer())
}
