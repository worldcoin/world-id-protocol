//! OPRF node Binary
//!
//! This is the main entry point for the OPRF node.
//! It initializes tracing, metrics, and starts the node with configuration
//! from command-line arguments or environment variables.

use std::{process::ExitCode, sync::Arc};

use clap::Parser;
use eyre::Context;
use taceo_oprf::service::secret_manager::postgres::PostgresSecretManager;
use world_id_oprf_node::config::WorldOprfNodeConfig;

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let tracing_config = taceo_nodes_observability::TracingConfig::try_from_env()?;
    let _tracing_handle = taceo_nodes_observability::initialize_tracing(&tracing_config)?;
    taceo_oprf::service::metrics::describe_metrics();
    world_id_oprf_node::metrics::describe_metrics();

    tracing::info!("{}", taceo_nodes_common::version_info!());

    let config = WorldOprfNodeConfig::parse();

    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        PostgresSecretManager::init(
            &config.node_config.db_connection_string,
            &config.node_config.db_schema,
            config.node_config.db_max_connections,
        )
        .await
        .context("while initializing Postgres secret manager")?,
    );

    let result = world_id_oprf_node::start(
        config,
        secret_manager,
        taceo_nodes_common::default_shutdown_signal(),
    )
    .await;
    match result {
        Ok(()) => {
            tracing::info!("good night!");
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            // we don't want to double print the error therefore we just return FAILURE
            tracing::error!("{err:?}");
            Ok(ExitCode::FAILURE)
        }
    }
}
