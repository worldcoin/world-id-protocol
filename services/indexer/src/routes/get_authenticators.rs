use crate::{config::AppState, error::IndexerErrorResponse};
use axum::{Json, extract::State};
use world_id_primitives::api_types::{
    IndexerAuthenticatorsResponse, IndexerErrorCode, IndexerQueryRequest,
};

/// Get Authenticators
///
/// Returns the registered authenticators of a World ID by leaf index: the compressed public key
/// and address of every slot, together with the offchain signer commitment and recovery counter,
/// all read from the same indexed state. Removed slots are `null`. Proving Authenticators have
/// the zero address.
#[utoipa::path(
    post,
    path = "/authenticators",
    request_body = IndexerQueryRequest,
    responses(
        (status = 200, body = IndexerAuthenticatorsResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerQueryRequest>,
) -> Result<Json<IndexerAuthenticatorsResponse>, IndexerErrorResponse> {
    if req.leaf_index == 0 {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::InvalidLeafIndex,
            "Leaf index cannot be 0.".to_string(),
        ));
    }

    let authenticators = state
        .db
        .accounts()
        .get_authenticators_by_leaf_index(req.leaf_index)
        .await
        .map_err(|err| {
            tracing::error!(leaf_index = %req.leaf_index, "DB error fetching authenticators: {err}");
            IndexerErrorResponse::internal_server_error()
        })?
        .ok_or(IndexerErrorResponse::not_found())?;

    if authenticators.authenticator_addresses.len() != authenticators.authenticator_pubkeys.len() {
        tracing::error!(
            leaf_index = %req.leaf_index,
            addresses = authenticators.authenticator_addresses.len(),
            pubkeys = authenticators.authenticator_pubkeys.len(),
            "Indexed authenticator addresses and pubkeys have different lengths"
        );
        return Err(IndexerErrorResponse::internal_server_error());
    }

    Ok(Json(IndexerAuthenticatorsResponse {
        authenticator_pubkeys: authenticators.authenticator_pubkeys,
        authenticator_addresses: authenticators.authenticator_addresses,
        offchain_signer_commitment: authenticators.offchain_signer_commitment,
        recovery_counter: authenticators.recovery_counter,
    }))
}
