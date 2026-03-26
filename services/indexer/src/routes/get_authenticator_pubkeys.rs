use super::LeafIndexPath;
use crate::{config::AppState, error::IndexerErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use world_id_core::api_types::{
    IndexerAuthenticatorPubkeysResponse, IndexerErrorCode, IndexerQueryRequest,
};

/// Get Authenticator Pubkeys
///
/// Returns the compressed authenticator public keys for a given World ID by leaf index.
/// Removed authenticator slots are returned as `null` to preserve `pubkey_id` positions.
#[utoipa::path(
    post,
    path = "/authenticator-pubkeys",
    request_body = IndexerQueryRequest,
    responses(
        (status = 200, body = IndexerAuthenticatorPubkeysResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerQueryRequest>,
) -> Result<Json<IndexerAuthenticatorPubkeysResponse>, IndexerErrorResponse> {
    handle_request(state, req).await
}

/// Get Authenticator Pubkeys (V2)
///
/// Returns the compressed authenticator public keys for a given World ID by leaf index.
/// Removed authenticator slots are returned as `null` to preserve `pubkey_id` positions.
#[utoipa::path(
    get,
    path = "/v2/accounts/{leaf_index}/authenticator-pubkeys",
    params(
        (
            "leaf_index" = String,
            Path,
            description = "The leaf index to query (accepts decimal or `0x`/`0X`-prefixed hex input).",
            example = "0x1"
        )
    ),
    responses(
        (status = 200, body = IndexerAuthenticatorPubkeysResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn v2_handler(
    State(state): State<AppState>,
    Path(path): Path<LeafIndexPath>,
) -> Result<Json<IndexerAuthenticatorPubkeysResponse>, IndexerErrorResponse> {
    handle_request(
        state,
        IndexerQueryRequest {
            leaf_index: path.leaf_index,
        },
    )
    .await
}

async fn handle_request(
    state: AppState,
    req: IndexerQueryRequest,
) -> Result<Json<IndexerAuthenticatorPubkeysResponse>, IndexerErrorResponse> {
    if req.leaf_index == 0 {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::InvalidLeafIndex,
            "Leaf index cannot be 0.".to_string(),
        ));
    }

    let (offchain_signer_commitment, authenticator_pubkeys) = state
        .db
        .accounts()
        .get_offchain_signer_commitment_and_authenticator_pubkeys_by_leaf_index(
            req.leaf_index,
        )
        .await
        .map_err(|err| {
            tracing::error!(leaf_index = %req.leaf_index, "DB error fetching authenticator pubkeys: {err}");
            IndexerErrorResponse::internal_server_error()
        })?
        .ok_or(IndexerErrorResponse::not_found())?;

    Ok(Json(IndexerAuthenticatorPubkeysResponse {
        authenticator_pubkeys,
        offchain_signer_commitment,
    }))
}
