use alloy::primitives::U256;
use axum::{extract::State, Json};
use world_id_core::types::{IndexerPackedAccountRequest, IndexerPackedAccountResponse};

use crate::{
    config::AppState,
    error::{ErrorBody, ErrorCode, ErrorResponse},
};

/// Get the packed account index by authenticator address from the `AccountRegistry` contract.
///
/// Returns the packed account index for a given authenticator address.
#[utoipa::path(
    post,
    path = "/packed_account",
    request_body = IndexerPackedAccountRequest,
    responses(
        (status = 200, description = "Successfully retrieved packed account index", body = IndexerPackedAccountResponse),
        (status = 400, description = "Account does not exist for the given authenticator address", body = ErrorBody),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerPackedAccountRequest>,
) -> Result<Json<IndexerPackedAccountResponse>, ErrorResponse> {
    let packed_account_data = state
        .registry
        .authenticatorAddressToPackedAccountData(req.authenticator_address)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting packed account index: {}", e);
            ErrorResponse::internal_server_error()
        })?;

    if packed_account_data == U256::ZERO {
        return Err(ErrorResponse::bad_request(
            ErrorCode::AccountDoesNotExist,
            "There is no account for this authenticator address".to_string(),
        ));
    }

    Ok(Json(IndexerPackedAccountResponse {
        packed_account_data,
    }))
}
