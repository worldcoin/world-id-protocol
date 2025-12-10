use alloy::primitives::U256;
use axum::{extract::State, Json};
use world_id_core::types::{IndexerQueryRequest, IndexerSignatureNonceResponse};

use crate::{
    config::AppState,
    error::{ErrorCode, ErrorResponse},
};

/// Get Signature Nonce
///
/// Returns the current signature nonce for a given World ID based on its leaf index. The nonce is
/// used to perform on-chain operations for the World ID.
///
/// If the provided leaf index is invalid, the nonce will still be returned as zero.
#[utoipa::path(
    post,
    path = "/signature-nonce",
    request_body = IndexerQueryRequest,
    responses(
        (status = 200, body = IndexerSignatureNonceResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerQueryRequest>,
) -> Result<Json<IndexerSignatureNonceResponse>, ErrorResponse> {
    if req.leaf_index == U256::ZERO {
        return Err(ErrorResponse::bad_request(
            ErrorCode::InvalidLeafIndex,
            "Account index cannot be zero".to_string(),
        ));
    }

    let signature_nonce = state
        .registry
        .leafIndexToSignatureNonce(req.leaf_index)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting signature nonce: {}", e);
            ErrorResponse::internal_server_error()
        })?;

    Ok(Json(IndexerSignatureNonceResponse { signature_nonce }))
}
