use alloy::primitives::U256;
use axum::{extract::State, Json};
use world_id_core::types::{
    IndexerErrorCode, IndexerErrorResponse, IndexerQueryRequest, IndexerSignatureNonceResponse,
};

use crate::config::AppState;

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
) -> Result<Json<IndexerSignatureNonceResponse>, IndexerErrorResponse> {
    if req.leaf_index == U256::ZERO {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::InvalidLeafIndex(req.leaf_index.to_string()),
        ));
    }

    let signature_nonce = state
        .registry
        .leafIndexToSignatureNonce(req.leaf_index)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting signature nonce: {}", e);
            IndexerErrorResponse::internal_server_error()
        })?;

    Ok(Json(IndexerSignatureNonceResponse { signature_nonce }))
}
