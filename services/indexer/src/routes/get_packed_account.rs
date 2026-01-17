use alloy::primitives::U256;
use axum::{Json, extract::State};
use world_id_core::types::{
    IndexerErrorBody, IndexerErrorCode, IndexerErrorResponse, IndexerPackedAccountRequest,
    IndexerPackedAccountResponse,
};

use crate::config::AppState;

/// Get Packed Account Data
///
/// Returns the packed account data for a given authenticator address from the `WorldIDRegistry` contract.
#[utoipa::path(
    post,
    summary = "Get Packed Account Data",
    path = "/packed-account",
    request_body = IndexerPackedAccountRequest,
    responses(
        (status = 200, body = IndexerPackedAccountResponse),
        (status = 400, description = "Account does not exist for the given authenticator address", body = IndexerErrorBody),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerPackedAccountRequest>,
) -> Result<Json<IndexerPackedAccountResponse>, IndexerErrorResponse> {
    let packed_account_data = state
        .registry
        .authenticatorAddressToPackedAccountData(req.authenticator_address)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting packed account index: {}", e);
            IndexerErrorResponse::internal_server_error()
        })?;

    if packed_account_data == U256::ZERO {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::AccountDoesNotExist,
            "There is no account for this authenticator address".to_string(),
        ));
    }

    Ok(Json(IndexerPackedAccountResponse {
        packed_account_data,
    }))
}
