use crate::error::{IndexerErrorBody, IndexerErrorResponse};
use alloy::primitives::U256;
use axum::{Json, extract::State};
use world_id_primitives::api_types::{
    IndexerErrorCode, IndexerPackedAccountRequest, IndexerPackedAccountResponse,
};

use crate::config::AppState;

/// Packed account data layout: `[32 bits recoveryCounter][32 bits pubkeyId][128 reserved][64 bits leafIndex]`.
/// See `contracts/src/core/libraries/PackedAccountData.sol`.
const RECOVERY_COUNTER_SHIFT: usize = 224;
const LEAF_INDEX_MASK: U256 = U256::from_limbs([u64::MAX, 0, 0, 0]);

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
        (status = 403, description = "Authenticator was revoked by recovery", body = IndexerErrorBody),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerPackedAccountRequest>,
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

    let leaf_index = (packed_account_data & LEAF_INDEX_MASK).to::<u64>();
    let packed_recovery_counter = packed_account_data >> RECOVERY_COUNTER_SHIFT;

    // Packed mappings for revoked authenticators remain on-chain after recovery.
    // Compare with the registry's current counter, not an eventually consistent
    // indexer row: a missing or lagging row must never authorize the old device.
    let current_recovery_counter = state
        .registry
        .getRecoveryCounter(leaf_index)
        .call()
        .await
        .map_err(|err| {
            tracing::error!(leaf_index, "RPC error fetching recovery counter: {err}");
            IndexerErrorResponse::internal_server_error()
        })?;

    if current_recovery_counter != packed_recovery_counter {
        return Err(IndexerErrorResponse::new(
            IndexerErrorCode::AuthenticatorRevoked,
            "This authenticator was revoked by an account recovery".to_string(),
            http::StatusCode::FORBIDDEN,
        ));
    }

    Ok(Json(IndexerPackedAccountResponse {
        packed_account_data,
    }))
}
