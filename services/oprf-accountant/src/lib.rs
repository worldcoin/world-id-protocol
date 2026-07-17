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

use axum::{Router, extract::FromRef};

use crate::{config::OprfAccountantConfig, postgres::PostgresDb};

pub mod api;
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

pub async fn start(_config: &OprfAccountantConfig, db: PostgresDb) -> Router {
    Router::new().merge(api::routes()).with_state(AppState(db))
}
