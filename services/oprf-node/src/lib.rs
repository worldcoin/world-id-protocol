#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
#![allow(
    clippy::cast_precision_loss,
    reason = "Is ok due to API limitations for metrics"
)]

//! This crate implements TACEO:Oprf for World ID.
//!
//! It provides an Axum based HTTP-server that computes distributed OPRF (Oblivious Pseudo-Random Function) functions to be used as nullifiers and session identifiers in the World ecosystem.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
use std::sync::Arc;

use ark_bn254::Bn254;
use circom_types::groth16::VerificationKey;
use eyre::Context;
use taceo_oprf::service::{
    OprfServiceBuilder, StartedServices, secret_manager::SecretManagerService,
};
use tokio_util::sync::CancellationToken;
use world_id_primitives::oprf::OprfModule;

use crate::{
    auth::{
        credential_blinding_factor::CredentialBlindingFactorModuleAuth,
        merkle_watcher::MerkleWatcher, nonce_history::NonceHistory, rp_module::RpModuleAuth,
        rp_registry_watcher::RpRegistryWatcher,
        schema_issuer_registry_watcher::SchemaIssuerRegistryWatcher,
    },
    config::WorldOprfNodeConfig,
};

/// The embedded Groth16 verification key for OPRF query proofs.
const QUERY_VERIFICATION_KEY: &str = include_str!("../../../circom/OPRFQuery.vk.json");

pub(crate) mod auth;
pub mod config;
pub mod metrics;

/// The tasks spawned by the oprf-node. Should call [`WorldOprfNodeTasks::join`] when shutting down for graceful shutdown.
#[allow(clippy::struct_field_names, reason = "Has the watcher suffix in name")]
pub struct WorldOprfNodeTasks {
    key_event_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
}

impl WorldOprfNodeTasks {
    /// Awaits all background tasks and propagates any errors.
    ///
    /// This consumes the struct and joins all internally tracked
    /// `tokio::task::JoinHandle`s. It waits for all tasks to finish
    /// and returns an error if any of them failed or panicked.
    ///
    /// # Errors
    /// Returns an error if:
    /// - any task returns an error, or
    /// - any task panics or is aborted.
    pub async fn join(self) -> eyre::Result<()> {
        self.key_event_watcher.await??;
        Ok(())
    }
}

/// Starts the OPRF node and initializes all required services.
///
/// This is the main entry point for running an OPRF node. It sets up all
/// watchers, authentication services, and the OPRF service itself, and
/// returns the HTTP router together with the spawned background tasks.
///
/// The initialization flow consists of:
/// - Initializing on-chain watchers:
///   - Merkle tree watcher (for identity commitments)
///   - RP registry watcher
///   - Credential schema issuer registry watcher
/// - Setting up request authentication services:
///   - Nullifier OPRF request authentication
///   - Credential blinding factor OPRF request authentication
/// - Initializing the OPRF service and registering its modules
/// - Constructing the Axum router for handling incoming HTTP requests
///
/// The returned [`WorldOprfNodeTasks`] contains all long-running background
/// tasks (key event handling).
///
/// # Arguments
/// - `config`: Full node configuration.
/// - `secret_manager`: Service responsible for managing oprf secret shares
/// - `cancellation_token`: Token used to gracefully shut down all services
///
/// # Returns
/// A tuple containing:
/// - The configured [`axum::Router`] for serving HTTP requests
/// - [`WorldOprfNodeTasks`] with all spawned background tasks
///
/// # Errors
/// Returns an error if any component fails to initialize.
#[allow(
    clippy::missing_panics_doc,
    reason = "Can realistically not panic as we embed the key at compile time"
)]
#[allow(
    clippy::too_many_lines,
    reason = "Still acceptable length for an init function"
)]
pub async fn start(
    config: WorldOprfNodeConfig,
    secret_manager: SecretManagerService,
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, WorldOprfNodeTasks)> {
    let node_config = config.node_config;
    let started_services = StartedServices::default();

    tracing::info!("connecting to RPC..");
    let http_rpc_provider =
        taceo_nodes_common::web3::HttpRpcProviderBuilder::with_config(&config.rpc_provider_config)
            .environment(node_config.environment)
            .build()
            .context("while init blockchain connection")?;

    tracing::info!("init merkle watcher..");
    let merkle_watcher = MerkleWatcher::init(
        config.world_id_registry_contract,
        &http_rpc_provider,
        config.merkle_cache_config,
    );

    tracing::info!("init RpRegistry watcher..");
    let rp_registry_watcher = RpRegistryWatcher::init(
        config.rp_registry_contract,
        http_rpc_provider.clone(),
        config.timeout_external_eth_call,
        config.rp_cache_config,
    );

    let query_vk = serde_json::from_str::<VerificationKey<Bn254>>(QUERY_VERIFICATION_KEY)
        .expect("can deserialize embedded vk");
    let query_vk = Arc::new(ark_groth16::prepare_verifying_key(&query_vk.into()));

    tracing::info!("init nullifier oprf request auth service..");
    let nullifier_oprf_req_auth_service = Arc::new(RpModuleAuth::new_uniqueness(
        merkle_watcher.clone(),
        rp_registry_watcher.clone(),
        NonceHistory::init(
            // keep cache for 2x so that we catch all replays that would be valid and some that would be invalid anyways
            config.current_time_stamp_max_difference * 2,
        ),
        config.current_time_stamp_max_difference,
        config.timeout_external_eth_call,
        http_rpc_provider.clone(),
        Arc::clone(&query_vk),
    ));

    tracing::info!("init session oprf request auth service..");
    // Session and uniqueness use separate nonce histories intentionally.
    // We use the same nonce for both signatures
    let session_oprf_req_auth_service = Arc::new(RpModuleAuth::new_session(
        merkle_watcher.clone(),
        rp_registry_watcher.clone(),
        NonceHistory::init(
            // keep cache for 2x so that we catch all replays that would be valid and some that would be invalid anyways
            config.current_time_stamp_max_difference * 2,
        ),
        config.current_time_stamp_max_difference,
        config.timeout_external_eth_call,
        http_rpc_provider.clone(),
        Arc::clone(&query_vk),
    ));

    tracing::info!("init CredentialSchemaIssuerRegistry watcher..");
    let schema_issuer_registry_watcher = SchemaIssuerRegistryWatcher::init(
        config.credential_schema_issuer_registry_contract,
        &http_rpc_provider,
        config.issuer_cache_config,
    );

    tracing::info!("init credential blinding factor oprf request auth service..");
    let credential_blinding_factor_oprf_req_auth_service =
        Arc::new(CredentialBlindingFactorModuleAuth::init(
            merkle_watcher,
            schema_issuer_registry_watcher,
            Arc::clone(&query_vk),
        ));

    tracing::info!("init oprf service..");
    let (router, key_event_watcher) = OprfServiceBuilder::init(
        node_config,
        secret_manager,
        http_rpc_provider.clone(),
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
    .module(
        &format!("/{}", OprfModule::Session),
        session_oprf_req_auth_service,
    )
    .build();
    let tasks = WorldOprfNodeTasks { key_event_watcher };

    Ok((router, tasks))
}
