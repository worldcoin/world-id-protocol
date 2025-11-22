use alloy::primitives::{Address, U256};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    config::AppState,
    error::{ErrorCode, ErrorResponse},
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct PackedAccountRequest {
    #[schema(value_type = String, format = "hex")]
    pub authenticator_address: Address,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackedAccountResponse {
    #[schema(value_type = String, format = "hex")]
    pub packed_account_index: U256,
}

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
