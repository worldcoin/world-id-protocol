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

use alloy::{providers::Provider, signers::local::PrivateKeySigner};
use axum::{Router, extract::FromRef};
use secrecy::ExposeSecret as _;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    accountant_service::{OprfAccountantService, OprfAccountantServiceArgs},
    config::OprfAccountantConfig,
    postgres::PostgresDb,
};

pub mod accountant_service;
pub mod api;
pub mod config;
pub mod metrics;
pub mod postgres;

#[derive(Clone)]
struct AppState {
    db: PostgresDb,
    accountant: OprfAccountantService,
}

impl FromRef<AppState> for PostgresDb {
    fn from_ref(input: &AppState) -> Self {
        input.db.clone()
    }
}

impl FromRef<AppState> for OprfAccountantService {
    fn from_ref(input: &AppState) -> Self {
        input.accountant.clone()
    }
}

pub async fn start(
    config: &OprfAccountantConfig,
    db: PostgresDb,
    cancellation_token: CancellationToken,
) -> eyre::Result<(Router, JoinHandle<()>)> {
    let provider =
        taceo_nodes_common::web3::HttpRpcProviderBuilder::with_config(&config.rpc_provider_config)
            .build()?;
    let signer: PrivateKeySigner = config.wallet_private_key.expose_secret().parse()?;

    let chain_id = provider.get_chain_id().await?;

    let accountant = OprfAccountantService::new(OprfAccountantServiceArgs {
        provider,
        chain_id,
        billing_contract: config.billing_contract,
        signer,
        db: db.clone(),
        tick_interval: config.tick_interval,
        vote_timeout: config.vote_timeout,
        voting_window_offset: config.voting_window_offset,
        billing_vote_chunk_size: config.billing_vote_chunk_size,
        cancellation_token: cancellation_token.clone(),
    });

    let accountant_task = tokio::spawn({
        let accountant = accountant.clone();
        async move {
            let _guard = cancellation_token.drop_guard_ref();
            accountant.run().await
        }
    });

    let app_state = AppState { db, accountant };

    let router = Router::new().merge(api::routes()).with_state(app_state);

    Ok((router, accountant_task))
}
