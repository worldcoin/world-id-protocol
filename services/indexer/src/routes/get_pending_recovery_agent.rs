use crate::error::IndexerErrorResponse;
use axum::{Json, extract::State};
use world_id_primitives::api_types::{
    IndexerErrorCode, IndexerPendingRecoveryAgentResponse, IndexerQueryRequest,
};

use crate::config::AppState;

/// Get the pending recovery agent update for a particular World ID given its leaf index.
///
/// If no recovery agent update is pending, the zero address and zero execute-after timestamp are returned.
#[utoipa::path(
    post,
    path = "/pending-recovery-agent",
    request_body = IndexerQueryRequest,
    responses(
        (status = 200, body = IndexerPendingRecoveryAgentResponse),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerQueryRequest>,
) -> Result<Json<IndexerPendingRecoveryAgentResponse>, IndexerErrorResponse> {
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

    let pending_recovery_agent_update = state
        .registry
        .getPendingRecoveryAgentUpdate(req.leaf_index)
        .call()
        .await
        .map_err(|e| {
            tracing::error!("RPC error getting pending recovery agent: {}", e);
            IndexerErrorResponse::internal_server_error()
        })?;

    Ok(Json(IndexerPendingRecoveryAgentResponse {
        pending_recovery_agent: pending_recovery_agent_update.newRecoveryAgent,
        execute_after: pending_recovery_agent_update.executeAfter,
    }))
}
