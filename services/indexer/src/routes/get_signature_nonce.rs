use alloy::primitives::U256;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    config::AppState,
    error::{ErrorCode, ErrorObject, ErrorResponse},
};

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({"account_index": "0x1"}))]
pub(super) struct SignatureNonceRequest {
    /// The account index to look up
    #[schema(value_type = String, format = "hex", example = "0x1")]
    pub account_index: U256,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({"signature_nonce": "0x0"}))]
pub(super) struct SignatureNonceResponse {
    /// The signature nonce for the account
    #[schema(value_type = String, format = "hex", example = "0x0")]
    pub signature_nonce: U256,
}

/// Get the signature nonce for a specific accountfrom the `AccountRegistry` contract.
///
/// Returns the signature nonce for a given account index.
#[utoipa::path(
    post,
    path = "/signature_nonce",
    request_body = SignatureNonceRequest,
    responses(
        (status = 200, description = "Successfully retrieved signature nonce", body = SignatureNonceResponse),
        (status = 400, description = "Invalid account index provided", body = ErrorObject),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<SignatureNonceRequest>,
) -> Result<Json<SignatureNonceResponse>, ErrorResponse> {
    if req.account_index == U256::ZERO {
        return Err(ErrorResponse::bad_request(
            ErrorCode::InvalidAccountIndex,
            "Account index cannot be zero".to_string(),
        ));
    }

    let signature_nonce = state
        .registry
        .signatureNonces(req.account_index)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting signature nonce: {}", e);
            ErrorResponse::internal_server_error()
        })?;

    Ok(Json(SignatureNonceResponse { signature_nonce }))
}
