//! WIP-107 billing registration handler.

use crate::{
    error::GatewayErrorResponse, request::IntoRequest, routes::middleware::RequestId,
    types::AppState,
};
use axum::{Extension, Json, extract::State};
use tracing::instrument;
use world_id_primitives::{api_types::GatewayStatusResponse, billing::BillingRegistration};

/// POST /register-billing
///
/// Relays a World ID's registration for a billing context to `WorldIDBilling.register`. Returns
/// 501 without a Billing Contract and 409 for an already registered billing nullifier.
#[instrument(name = "register_billing", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn register_billing(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<BillingRegistration>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id, &state.ctx)
        .await?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
