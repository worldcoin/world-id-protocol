use alloy::signers::Signature;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use world_id_primitives::{oprf::NullifierOprfRequestAuthV1, rp::RpId};

use crate::{AppState, accountant_service::OprfAccountantService};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BillableRpRequest {
    pub rp_id: RpId,
    #[serde(with = "ark_serde_compat::field")]
    pub nonce: ark_babyjubjub::Fq,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(with = "ark_serde_compat::field")]
    pub action: ark_babyjubjub::Fq,
    pub signature: Option<Signature>,
}

impl From<&NullifierOprfRequestAuthV1> for BillableRpRequest {
    fn from(value: &NullifierOprfRequestAuthV1) -> Self {
        let NullifierOprfRequestAuthV1 {
            action,
            nonce,
            current_time_stamp,
            expiration_timestamp,
            signature,
            rp_id,
            ..
        } = value;
        Self {
            rp_id: *rp_id,
            nonce: *nonce,
            action: *action,
            expires_at: *expiration_timestamp,
            created_at: *current_time_stamp,
            signature: *signature,
        }
    }
}

#[instrument(level = "info", skip_all)]
async fn post_request(
    State(accountant): State<OprfAccountantService>,
    Json(rp_requests): Json<Vec<BillableRpRequest>>,
) -> impl IntoResponse {
    match accountant.record_rp_request_batch(rp_requests).await {
        Ok(()) => {
            tracing::trace!("Successfully recorded RP request batch");
            StatusCode::OK
        }
        Err(err) => {
            tracing::error!(?err, "Failed to record RP request batch: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/req", post(post_request))
}
