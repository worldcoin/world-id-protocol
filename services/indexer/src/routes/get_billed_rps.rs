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
///
/// An explicit degraded mode: until the sync catches up, and once the synced block is older than
/// `BILLING_MAX_SYNC_AGE_SECS`, this endpoint answers `503` while the rest of the API keeps
/// serving.
#[utoipa::path(
    get,
    path = "/billing/billed-rps",
    responses(
        (status = 200, body = IndexerBilledRpsResponse),
        (status = 404, description = "This indexer does not index a Billing Contract", body = crate::error::IndexerErrorBody),
        (status = 503, description = "The Billing Contract sync has not caught up yet, or is resyncing after a reorganization (`billing_not_synced`), or its synced block is too old (`billing_sync_stale`)", body = crate::error::IndexerErrorBody),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
) -> Result<Json<IndexerBilledRpsResponse>, IndexerErrorResponse> {
    let Some(billing) = state.billing else {
        return Err(IndexerErrorResponse::not_found());
    };
    let not_synced = || {
        IndexerErrorResponse::new(
            IndexerErrorCode::BillingNotSynced,
            "The Billing Contract sync has not caught up yet.".to_string(),
            StatusCode::SERVICE_UNAVAILABLE,
        )
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
        .ok_or_else(not_synced)?;
    let synced_at = billed.synced_at.ok_or_else(not_synced)?;

    let age = unix_now().saturating_sub(synced_at);
    if age > billing.max_sync_age_secs {
        tracing::warn!(
            billing_contract = %billing.address,
            age_secs = age,
            block_number = billed.block_number,
            "serving 503: the Billing Contract sync has fallen behind"
        );
        return Err(IndexerErrorResponse::new(
            IndexerErrorCode::BillingSyncStale,
            format!("The Billing Contract's synced block is {age}s old."),
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }

    Ok(Json(IndexerBilledRpsResponse {
        chain_id: billed.chain_id,
        billing_contract: billing.address,
        block_number: billed.block_number,
        synced_at,
        billed_rp_ids: billed.rp_ids.into_iter().map(RpId::new).collect(),
    }))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
