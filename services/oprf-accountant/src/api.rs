use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use world_id_primitives::{oprf::NullifierOprfRequestAuthV1, rp::RpId};

use crate::{AppState, postgres::PostgresDb};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PostRequestQuery {
    pub id: Uuid,
}

impl PostRequestQuery {
    pub fn into_query_strings(self) -> (String, String) {
        (String::from("id"), self.id.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BillableRpRequest {
    pub rp_id: RpId,
    #[serde(with = "ark_serde_compat::field")]
    pub nonce: ark_babyjubjub::Fq,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(with = "ark_serde_compat::field")]
    pub action: ark_babyjubjub::Fq,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<alloy_primitives::Signature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "world_id_primitives::serde_utils::hex_bytes_opt")]
    pub wip101_data: Option<Vec<u8>>,
}

impl From<&NullifierOprfRequestAuthV1> for BillableRpRequest {
    fn from(value: &NullifierOprfRequestAuthV1) -> Self {
        let NullifierOprfRequestAuthV1 {
            action,
            nonce,
            created_at,
            expires_at,
            signature,
            rp_id,
            wip101_data,
            ..
        } = value;
        Self {
            rp_id: *rp_id,
            nonce: *nonce,
            action: *action,
            expires_at: *expires_at,
            created_at: *created_at,
            signature: *signature,
            wip101_data: wip101_data.clone(),
        }
    }
}

// TODO add id to span
async fn post_request(
    State(db): State<PostgresDb>,
    Query(PostRequestQuery { id: _ }): Query<PostRequestQuery>,
    Json(rp_requests): Json<Vec<BillableRpRequest>>,
) -> impl IntoResponse {
    // TODO get the epochs for the RpVote from the contract
    let _ = db.store_request_batch(rp_requests).await;
    StatusCode::OK
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/req", post(post_request))
}
