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
use tokio_util::sync::CancellationToken;
use world_id_primitives::oprf::OprfModule;

use crate::{
    auth::{
        credential_blinding_factor::CredentialBlindingFactorOprfRequestAuthenticator,
        merkle_watcher::MerkleWatcher, nullifier::NullifierOprfRequestAuthenticator,
        rp_registry_watcher::RpRegistryWatcher,
        schema_issuer_registry_watcher::SchemaIssuerRegistryWatcher,
        signature_history::SignatureHistory,
    },
    config::WorldOprfNodeConfig,
};

pub(crate) mod auth;
pub mod config;
pub mod metrics;

/// The tasks spawned by the oprf-node. Should call [`WorldOprfNodeTasks::join`] when shutting down for graceful shutdown.
pub struct WorldOprfNodeTasks {
    key_event_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
    merkle_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
    rp_registry_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
    schema_issuer_registry_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
}

impl WorldOprfNodeTasks {
    /// Consumes the task by joining every registered `JoinHandle`.
    pub async fn join(self) -> eyre::Result<()> {
        let (
            key_event_watcher,
            merkle_watcher,
            rp_registry_watcher,
            schema_issuer_registry_watcher,
        ) = tokio::join!(
            self.key_event_watcher,
            self.merkle_watcher,
            self.rp_registry_watcher,
            self.schema_issuer_registry_watcher
        );
        key_event_watcher??;
        merkle_watcher??;
        rp_registry_watcher??;
        schema_issuer_registry_watcher??;
        Ok(())
    }
}

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
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, WorldOprfNodeTasks)> {
    let node_config = config.node_config;
    let started_services = StartedServices::default();

    tracing::info!("init merkle watcher..");
    let (merkle_watcher, merkle_watcher_task) = MerkleWatcher::init(
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
    let (rp_registry_watcher, rp_registry_watcher_task) = RpRegistryWatcher::init(
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

    tracing::info!("init nullifier oprf request auth service..");
    let nullifier_oprf_req_auth_service = Arc::new(NullifierOprfRequestAuthenticator::init(
        merkle_watcher.clone(),
        rp_registry_watcher.clone(),
        signature_history,
        config.current_time_stamp_max_difference,
    ));

    tracing::info!("init CredentialSchemaIssuerRegistry watcher..");
    let (schema_issuer_registry_watcher, schema_issuer_registry_watcher_task) =
        SchemaIssuerRegistryWatcher::init(
            config.credential_schema_issuer_registry_contract,
            node_config.chain_ws_rpc_url.expose_secret(),
            config.max_credential_schema_issuer_registry_store_size,
            config.cache_maintenance_interval,
            started_services.new_service(),
            cancellation_token.clone(),
        )
        .await
        .context("while starting schema issuer registry watcher")?;

    tracing::info!("init credential blinding factor oprf request auth service..");
    let credential_blinding_factor_oprf_req_auth_service =
        Arc::new(CredentialBlindingFactorOprfRequestAuthenticator::init(
            merkle_watcher,
            schema_issuer_registry_watcher,
        ));

    tracing::info!("init oprf service..");
    let (router, key_event_watcher) = OprfServiceBuilder::init(
        node_config,
        secret_manager,
        started_services,
        cancellation_token.clone(),
    )
    .await?
    .module(
        &format!("/{}", OprfModule::Nullifier),
        nullifier_oprf_req_auth_service,
    )
    .module(
        &format!("/{}", OprfModule::CredentialBlindingFactor),
        credential_blinding_factor_oprf_req_auth_service,
    )
    .build();

    let tasks = WorldOprfNodeTasks {
        key_event_watcher,
        merkle_watcher: merkle_watcher_task,
        rp_registry_watcher: rp_registry_watcher_task,
        schema_issuer_registry_watcher: schema_issuer_registry_watcher_task,
    };

    Ok((router, tasks))
}
