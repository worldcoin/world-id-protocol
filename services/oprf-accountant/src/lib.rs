// #![deny(clippy::all, clippy::pedantic)]
// #![deny(
//     clippy::allow_attributes_without_reason,
//     clippy::assertions_on_result_states,
//     clippy::dbg_macro,
//     clippy::decimal_literal_representation,
//     clippy::exhaustive_enums,
//     clippy::exhaustive_structs,
//     clippy::iter_over_hash_type,
//     clippy::let_underscore_must_use,
//     clippy::missing_assert_message,
//     clippy::print_stderr,
//     clippy::print_stdout,
//     clippy::undocumented_unsafe_blocks,
//     clippy::unnecessary_safety_comment,
//     clippy::unwrap_used
// )]
// #![allow(missing_docs, reason = "scaffold crate, docs not written yet")]

//! This crate implements the OPRF accountant for World ID.
//!
//! It provides an Axum based HTTP server.

use axum::{
    Json, Router,
    extract::{FromRef, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
use world_id_primitives::rp::RpId;

use crate::{config::OprfAccountantConfig, postgres::PostgresDb};

pub mod config;
pub mod metrics;
pub mod postgres;

#[derive(Clone)]
struct AppState(PostgresDb);

impl FromRef<AppState> for PostgresDb {
    fn from_ref(input: &AppState) -> Self {
        input.0.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpVote {
    rp_id: RpId,
    epoch: i64,
    #[serde(with = "ark_serde_compat::field")]
    nonce: ark_babyjubjub::Fq,
    created_at: u64,
    expires_at: u64,
    #[serde(with = "ark_serde_compat::field")]
    action: ark_babyjubjub::Fq,
    signature: Vec<u8>,
}

async fn post_request(
    State(db): State<PostgresDb>,
    Json(rp_requests): Json<Vec<RpVote>>,
) -> impl IntoResponse {
    let _ = db.store_request_batch(rp_requests).await;
    StatusCode::OK
}

pub async fn start(_config: &OprfAccountantConfig, db: PostgresDb) -> Router {
    Router::new()
        .route("/req", post(post_request))
        .with_state(AppState(db))
}
