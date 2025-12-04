//! OPRF node Binary
//!
//! This is the main entry point for the OPRF node.
//! It initializes tracing, metrics, and starts the node with configuration
//! from command-line arguments or environment variables.

use std::{process::ExitCode, sync::Arc};

use clap::Parser;
use oprf_service::{config::Environment, secret_manager::aws::AwsSecretManager};
use world_id_oprf_node::config::WorldOprfNodeConfig;

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let tracing_config = nodes_telemetry::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_telemetry::initialize_tracing(&tracing_config)?;
    oprf_service::metrics::describe_metrics();

    tracing::info!("{}", oprf_service::version_info());

    let config = WorldOprfNodeConfig::parse();

    let aws_config = match config.node_config.environment {
        Environment::Prod => aws_config::load_from_env().await,
        Environment::Dev => oprf_service::secret_manager::aws::localstack_aws_config().await,
    };

    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        AwsSecretManager::init(
            aws_config,
            &config.node_config.rp_secret_id_prefix,
            &config.node_config.wallet_private_key_secret_id,
        )
        .await,
    );

    let result = world_id_oprf_node::start(
        config,
        secret_manager,
        oprf_service::default_shutdown_signal(),
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
