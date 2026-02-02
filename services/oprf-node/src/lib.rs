#![deny(missing_docs)]
//! This crate implements TACEO:Oprf for World ID.
//!
//! It provides an Axum based HTTP-server that computes distributed OPRF (Oblivious Pseudo-Random Function) functions to be used as nullifiers in the World ecosystem.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
use std::sync::Arc;

use eyre::Context;
use secrecy::ExposeSecret;
use taceo_oprf::service::{
    OprfServiceBuilder, StartedServices, secret_manager::SecretManagerService,
};
use world_id_primitives::oprf::OprfModule;

use crate::{
    auth::{
        issuer::SchemaIssuerOprfRequestAuthenticator, merkle_watcher::MerkleWatcher,
        rp::RpOprfRequestAuthenticator, rp_registry_watcher::RpRegistryWatcher,
        schema_issuer_registry_watcher::SchemaIssuerRegistryWatcher,
        signature_history::SignatureHistory,
    },
    config::WorldOprfNodeConfig,
};

pub(crate) mod auth;
pub mod config;
pub mod metrics;

/// Main entry point for an OPRF node.
///
/// This function initializes and starts the OPRF node, including its various components, and
/// gracefully handles shutdown signals. The node performs the following tasks:
/// - Loads the Groth16 verification key for user proof validation.
/// - Initializes the Merkle watcher for monitoring on-chain events.
/// - Sets up the OPRF request authentication service.
/// - Initializes the OPRF node and its associated key event watcher.
/// - Starts an Axum-based HTTP server for handling incoming requests.
pub async fn start(
    config: WorldOprfNodeConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-node with config: {config:#?}");
    let node_config = config.node_config;
    let cancellation_token = taceo_nodes_common::spawn_shutdown_task(shutdown_signal);
    let mut started_services = StartedServices::default();

    tracing::info!("init merkle watcher..");
    let merkle_watcher = MerkleWatcher::init(
        config.world_id_registry_contract,
        node_config.chain_ws_rpc_url.expose_secret(),
        config.max_merkle_cache_size,
        config.cache_maintenance_interval,
        started_services.new_service(),
        cancellation_token.clone(),
    )
    .await
    .context("while starting merkle watcher")?;

    tracing::info!("init RpRegistry watcher..");
    let rp_registry_watcher = RpRegistryWatcher::init(
        config.rp_registry_contract,
        node_config.chain_ws_rpc_url.expose_secret(),
        config.max_rp_registry_store_size,
        config.cache_maintenance_interval,
        started_services.new_service(),
        cancellation_token.clone(),
    )
    .await
    .context("while starting merkle watcher")?;

    tracing::info!("init SignatureHistory..");
    // keep cache for 2x so that we catch all replays that would be valid and some that would be invalid anyways
    let signature_history = SignatureHistory::init(
        config.current_time_stamp_max_difference * 2,
        config.cache_maintenance_interval,
    );

    tracing::info!("init rp oprf request auth service..");
    let rp_oprf_req_auth_service = Arc::new(RpOprfRequestAuthenticator::init(
        merkle_watcher.clone(),
        rp_registry_watcher.clone(),
        signature_history,
        config.current_time_stamp_max_difference,
    ));

    tracing::info!("init CredentialSchemaIssuerRegistry watcher..");
    let schema_issuer_registry_watcher = SchemaIssuerRegistryWatcher::init(
        config.credential_schema_issuer_registry_contract,
        node_config.chain_ws_rpc_url.expose_secret(),
        config.max_credential_schema_issuer_registry_store_size,
        config.cache_maintenance_interval,
        started_services.new_service(),
        cancellation_token.clone(),
    )
    .await
    .context("while starting schema issuer registry watcher")?;

    tracing::info!("init schema issuer oprf request auth service..");
    let schema_issuer_oprf_req_auth_service = Arc::new(SchemaIssuerOprfRequestAuthenticator::init(
        merkle_watcher,
        schema_issuer_registry_watcher,
    ));

    tracing::info!("init oprf service..");
    let (oprf_service_router, key_event_watcher) = OprfServiceBuilder::init(
        node_config,
        secret_manager,
        started_services,
        cancellation_token.clone(),
    )
    .await?
    .module(
        &format!("/{}", OprfModule::Nullifier),
        rp_oprf_req_auth_service,
    )
    .module(
        &format!("/{}", OprfModule::CredentialBlindingFactor),
        schema_issuer_oprf_req_auth_service,
    )
    .build();

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = axum::serve(listener, oprf_service_router)
            .with_graceful_shutdown(async move { axum_shutdown_signal.cancelled().await })
            .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!("got error from axum: {err:?}");
        }
        // we cancel the token in case axum encountered an error to shutdown the service
        axum_cancel_token.cancel();
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, async move {
        tokio::join!(server, key_event_watcher)
    })
    .await
    {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => tracing::warn!("could not finish shutdown in time"),
    }

    Ok(())
}
