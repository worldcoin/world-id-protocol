use super::LeafIndexPath;
use crate::error::IndexerErrorResponse;
use axum::{
    Json,
    extract::{Path, State},
};
use world_id_core::api_types::{
    IndexerErrorCode, IndexerQueryRequest, IndexerRecoveryAgentResponse,
};

use crate::config::AppState;

/// Get the Recovery Agent for a particular World ID given its leaf index.
///
/// If no recovery agent is set, the zero address is returned.
#[utoipa::path(
    post,
    path = "/recovery-agent",
    request_body = IndexerQueryRequest,
    responses(
        (status = 200, body = IndexerRecoveryAgentResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerQueryRequest>,
) -> Result<Json<IndexerRecoveryAgentResponse>, IndexerErrorResponse> {
    handle_request(state, req).await
}

/// Get the Recovery Agent for a particular World ID given its leaf index (V2).
///
/// If no recovery agent is set, the zero address is returned.
#[utoipa::path(
    get,
    path = "/v2/accounts/{leaf_index}/recovery-agent",
    params(
        (
            "leaf_index" = String,
            Path,
            description = "The leaf index to query (accepts decimal or `0x`/`0X`-prefixed hex input).",
            example = "0x1"
        )
    ),
    responses(
        (status = 200, body = IndexerRecoveryAgentResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn v2_handler(
    State(state): State<AppState>,
    Path(path): Path<LeafIndexPath>,
) -> Result<Json<IndexerRecoveryAgentResponse>, IndexerErrorResponse> {
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
) -> Result<Json<IndexerRecoveryAgentResponse>, IndexerErrorResponse> {
    if req.leaf_index == 0 {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::InvalidLeafIndex,
            "Account index cannot be zero".to_string(),
        ));
    }

    if !state
        .db
        .accounts()
        .get_account_exists(req.leaf_index)
        .await
        .map_err(|e| {
            tracing::error!("DB error checking account existence: {}", e);
            IndexerErrorResponse::internal_server_error()
        })?
    {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::AccountDoesNotExist,
            "Leaf index does not exist.".to_string(),
        ));
    }

    let recovery_agent = state
        .registry
        .getRecoveryAgent(req.leaf_index)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting recovery agent: {}", e);
            IndexerErrorResponse::internal_server_error()
        })?;

    Ok(Json(IndexerRecoveryAgentResponse { recovery_agent }))
}
