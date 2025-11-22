use alloy::primitives::{Address, U256};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    config::AppState,
    error::{ErrorCode, ErrorObject, ErrorResponse},
};

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({"authenticator_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"}))]
pub struct PackedAccountRequest {
    /// The authenticator address to look up
    #[schema(value_type = String, format = "hex", example = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb")]
    pub authenticator_address: Address,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({"packed_account_index": "0x1"}))]
pub struct PackedAccountResponse {
    /// The packed account index [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
    #[schema(value_type = String, format = "hex", example = "0x1")]
    pub packed_account_index: U256,
}

/// Get the packed account index by authenticator address from the `AccountRegistry` contract.
///
/// Returns the packed account index for a given authenticator address.
#[utoipa::path(
    post,
    path = "/packed_account",
    request_body = PackedAccountRequest,
    responses(
        (status = 200, description = "Successfully retrieved packed account index", body = PackedAccountResponse),
        (status = 400, description = "Account does not exist for the given authenticator address", body = ErrorObject),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<PackedAccountRequest>,
) -> Result<Json<PackedAccountResponse>, ErrorResponse> {
    let packed_account_index = state
        .registry
        .authenticatorAddressToPackedAccountIndex(req.authenticator_address)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting packed account index: {}", e);
            ErrorResponse::internal_server_error()
        })?;

    if packed_account_index == U256::ZERO {
        return Err(ErrorResponse::bad_request(
            ErrorCode::AccountDoesNotExist,
            "There is no account for this authenticator address".to_string(),
        ));
    }

    Ok(Json(PackedAccountResponse {
        packed_account_index,
    }))
}
