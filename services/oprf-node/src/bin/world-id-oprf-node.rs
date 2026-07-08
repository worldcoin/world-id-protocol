//! OPRF node Binary
//!
//! This is the main entry point for the OPRF node.
//! It initializes tracing, metrics, and starts the node with configuration
//! from command-line arguments or environment variables.

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use config::{Config, Environment};
use eyre::Context;
use serde::Deserialize;
use taceo_nodes_common::postgres::PostgresConfig;
use taceo_oprf::service::secret_manager::{SecretManager, postgres::PostgresSecretManager};
use world_id_oprf_node::{
    accountant_batcher::{self, AccountantBatcherConfig},
    config::WorldOprfNodeConfig,
};

#[derive(Clone, Debug, Deserialize)]
struct FullWorldOprfNodeConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    /// The OPRF service config
    #[serde(rename = "service")]
    pub node_config: WorldOprfNodeConfig,
    /// The postgres config for the secret-manager
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,
    /// The config for the accountant batcher worker
    #[serde(rename = "batcher")]
    pub accountant_batcher_config: AccountantBatcherConfig,
    /// The timeout for the reqwest client that talks to the OPRF-accountant
    #[serde(with = "humantime_serde", default = "default_http_accountant_timeout")]
    pub http_accountant_timeout: Duration,
}

// we are not allowed to build an eyre::Report yet because telemetry-batteries expects to install
// the color-eyre hook
fn load_world_id_config() -> Result<FullWorldOprfNodeConfig, config::ConfigError> {
    let cfg = Config::builder().add_source(
        Environment::with_prefix("TACEO_OPRF_NODE")
            .separator("__")
            .list_separator(",")
            .with_list_parse_key("service.rpc.http_urls")
            .try_parsing(true),
    );

    let oprf_config = cfg.build()?.try_deserialize()?;

    // Unset all env vars with our prefix to prevent leakage to subprocesses.
    // Safety: this is called before any threads are spawned.
    let keys_to_remove: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| k.starts_with("TACEO_OPRF_NODE").then_some(k))
        .collect();
    for key in keys_to_remove {
        // SAFETY: no other threads are running at this point in the startup sequence.
        unsafe {
            std::env::remove_var(&key);
        }
    }

    Ok(oprf_config)
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

fn default_http_accountant_timeout() -> Duration {
    Duration::from_secs(30)
}

async fn run(config: FullWorldOprfNodeConfig) -> eyre::Result<()> {
    tracing::info!("{}", taceo_nodes_common::version_info!());
    tracing::info!("starting oprf-node with config: {config:#?}");

    // Load the postgres secret manager.
    tracing::info!("connect to postgres secret-manager..");
    let secret_manager = Arc::new(
        PostgresSecretManager::init(&config.postgres_config)
            .await
            .context("while starting postgres secret-manager")?,
    );

    let (cancellation_token, _) =
        taceo_nodes_common::spawn_shutdown_task(taceo_nodes_common::default_shutdown_signal());

    let client = reqwest::ClientBuilder::new()
        .timeout(config.http_accountant_timeout)
        .build()
        .context("while building reqwest client")?;

    let (accountant_batcher, accountant_batcher_task) = accountant_batcher::init(
        &config.accountant_batcher_config,
        client,
        cancellation_token.clone(),
    );

    // Clone the values we need afterwards
    let bind_addr = config.bind_addr;

    let node_information = secret_manager
        .load_node_information()
        .await
        .context("while loading node information")?;

    tracing::info!("starting world-node service...");
    let oprf_service_router = world_id_oprf_node::start(
        config.node_config,
        secret_manager,
        &node_information,
        accountant_batcher.clone(),
    )?;

    tracing::info!("starting axum server on {bind_addr}",);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let serve_result = axum::serve(listener, oprf_service_router)
        .with_graceful_shutdown(async move { cancellation_token.cancelled().await })
        .await;
    tracing::info!("axum server shutdown");
    tracing::info!("waiting for accountant batcher to finish processing...");
    accountant_batcher.close().await;
    accountant_batcher_task.await?;
    serve_result.context("while serving axum")?;
    Ok(())
}

fn main() -> ExitCode {
    // try loading config and unsetting vars before we do any potentially multithreaded work;
    let maybe_config = load_world_id_config();

    // we panic if we cannot setup tracing + TLS - if that fails we won't see anything anyways on tracing endpoint
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Can build Tokio runtime");
    runtime.block_on(async {
        let _guard = telemetry_batteries::init();
        world_id_oprf_node::metrics::describe_metrics();
        // load the config
        let config = match maybe_config {
            Ok(config) => config,
            Err(err) => {
                tracing::error!("failed to load config: {err}");
                return ExitCode::FAILURE;
            }
        };

        match run(config).await {
            Ok(_) => {
                tracing::info!("good night");
                ExitCode::SUCCESS
            }
            Err(err) => {
                tracing::error!(?err, "oprf-node did shutdown");
                tracing::error!("good night anyways");
                ExitCode::FAILURE
            }
        }
    })
}
