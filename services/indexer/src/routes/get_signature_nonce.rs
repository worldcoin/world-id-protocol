use alloy::primitives::U256;
use axum::{extract::State, Json};
use world_id_core::types::{IndexerSignatureNonceRequest, IndexerSignatureNonceResponse};

use crate::{
    config::AppState,
    error::{ErrorCode, ErrorResponse},
};

/// Get the signature nonce for a specific accountfrom the `AccountRegistry` contract.
///
/// Returns the signature nonce for a given account index.
#[utoipa::path(
    post,
    path = "/signature_nonce",
    request_body = IndexerSignatureNonceRequest,
    responses(
        (status = 200, description = "Successfully retrieved signature nonce", body = IndexerSignatureNonceResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerSignatureNonceRequest>,
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
