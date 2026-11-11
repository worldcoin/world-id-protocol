use axum::{Json, extract::State, http::StatusCode};
use world_id_primitives::{
    api_types::{IndexerBilledRpsResponse, IndexerErrorCode},
    rp::RpId,
};

use crate::{config::AppState, error::IndexerErrorResponse};

/// Billed RPs
///
/// Returns the RPs the WIP-107 Billing Contract bills, as of the last block the indexer synced its
/// events through. Clients compare `chain_id` and `billing_contract` with the contract they
/// expect.
#[utoipa::path(
    get,
    path = "/billing/billed-rps",
    responses(
        (status = 200, body = IndexerBilledRpsResponse),
        (status = 404, description = "This indexer does not index a Billing Contract", body = crate::error::IndexerErrorBody),
        (status = 503, description = "The Billing Contract has not been synced yet", body = crate::error::IndexerErrorBody),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
) -> Result<Json<IndexerBilledRpsResponse>, IndexerErrorResponse> {
    let Some(billing) = state.billing else {
        return Err(IndexerErrorResponse::not_found());
    };
    let billed = state
        .db
        .billing(billing.address)
        .billed_rps()
        .await
        .map_err(|error| {
            tracing::error!(%error, billing_contract = %billing.address, "failed to read the billed RPs");
            IndexerErrorResponse::internal_server_error()
        })?
        .ok_or_else(|| {
            IndexerErrorResponse::new(
                IndexerErrorCode::BillingNotSynced,
                "The Billing Contract has not been synced yet.".to_string(),
                StatusCode::SERVICE_UNAVAILABLE,
            )
        })?;

    Ok(Json(IndexerBilledRpsResponse {
        chain_id: billing.chain_id,
        billing_contract: billing.address,
        block_number: billed.block_number,
        billed_rp_ids: billed.rp_ids.into_iter().map(RpId::new).collect(),
    }))
}
