use super::AuthenticatorAddressPath;
use crate::error::{IndexerErrorBody, IndexerErrorResponse};
use alloy::primitives::U256;
use axum::{
    Json,
    extract::{Path, State},
};
use world_id_core::api_types::{
    IndexerErrorCode, IndexerPackedAccountRequest, IndexerPackedAccountResponse,
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
    handle_request(state, req).await
}

/// Get Packed Account Data (V2)
///
/// Returns the packed account data for a given authenticator address from the `WorldIDRegistry` contract.
#[utoipa::path(
    get,
    summary = "Get Packed Account Data",
    path = "/v2/authenticators/{authenticator_address}/packed-account",
    params(
        (
            "authenticator_address" = String,
            Path,
            description = "The authenticator EVM address to look up.",
            example = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
        )
    ),
    responses(
        (status = 200, body = IndexerPackedAccountResponse),
        (status = 400, description = "Account does not exist for the given authenticator address", body = IndexerErrorBody),
    ),
    tag = "indexer"
)]
pub(crate) async fn v2_handler(
    State(state): State<AppState>,
    Path(path): Path<AuthenticatorAddressPath>,
) -> Result<Json<IndexerPackedAccountResponse>, IndexerErrorResponse> {
    handle_request(
        state,
        IndexerPackedAccountRequest {
            authenticator_address: path.authenticator_address,
        },
    )
    .await
}

async fn handle_request(
    state: AppState,
    req: IndexerPackedAccountRequest,
) -> Result<Json<IndexerPackedAccountResponse>, IndexerErrorResponse> {
    let packed_account_data = state
        .registry
        .getPackedAccountData(req.authenticator_address)
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
