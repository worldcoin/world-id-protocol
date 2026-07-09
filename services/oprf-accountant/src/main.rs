//! OPRF accountant Binary
//!
//! This is the main entry point for the OPRF accountant.
//! It initializes tracing, metrics, and starts the service with configuration
//! from environment variables.

use axum::Router;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::{net::SocketAddr, process::ExitCode, time::Duration};

use config::{Config, Environment};
use eyre::Context;
use serde::Deserialize;
use world_id_oprf_accountant::{config::OprfAccountantConfig, postgres::PostgresDb};

#[derive(Clone, Debug, Deserialize)]
struct FullOprfAccountantConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF accountant service config
    #[serde(rename = "service")]
    pub service_config: OprfAccountantConfig,
}

// we are not allowed to build an eyre::Report yet because telemetry-batteries expects to install
// the color-eyre hook
fn load_oprf_accountant_config() -> Result<FullOprfAccountantConfig, config::ConfigError> {
    let cfg = Config::builder().add_source(
        Environment::with_prefix("TACEO_OPRF_ACCOUNTANT")
            .separator("__")
            .try_parsing(true),
    );

    let accountant_config = cfg.build()?.try_deserialize()?;

    // Unset all env vars with our prefix to prevent leakage to subprocesses.
    // Safety: this is called before any threads are spawned.
    let keys_to_remove: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| k.starts_with("TACEO_OPRF_ACCOUNTANT").then_some(k))
        .collect();
    for key in keys_to_remove {
        // SAFETY: no other threads are running at this point in the startup sequence.
        unsafe {
            std::env::remove_var(&key);
        }
    }

    Ok(accountant_config)
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4322".parse().expect("valid SocketAddr")
}

fn default_max_wait_shutdown() -> Duration {
    Duration::from_secs(10)
}

async fn run(config: FullOprfAccountantConfig) -> eyre::Result<()> {
    tracing::info!("{}", taceo_nodes_common::version_info!());
    tracing::info!("starting oprf-accountant with config: {config:#?}");

    let (cancellation_token, _) =
        taceo_nodes_common::spawn_shutdown_task(taceo_nodes_common::default_shutdown_signal());

    let db = PostgresDb::init(&config.service_config.postgres_config).await?;
    // Clone the values we need afterwards
    let bind_addr = config.bind_addr;
    let max_wait_time_shutdown = config.max_wait_time_shutdown;

    let (accountant_router, accountant_tasks) =
        world_id_oprf_accountant::start(&config.service_config, db, cancellation_token.clone())
            .await?;

    let router = Router::new()
        .merge(taceo_nodes_common::api::routes(
            taceo_nodes_common::version_info!(),
        ))
        .merge(accountant_router);

    let server = tokio::spawn({
        let cancellation_token = cancellation_token.clone();
        async move {
            // we cancel the token if this task closes for some reason
            let _drop_guard = cancellation_token.drop_guard_ref();
            tracing::info!("starting axum server on to {bind_addr}");
            let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .context("while binding tcp-listener")?;
            let axum_result = axum::serve(tcp_listener, router)
                .with_graceful_shutdown({
                    let cancellation_token = cancellation_token.clone();
                    async move { cancellation_token.cancelled().await }
                })
                .await
                .context("while running axum");
            tracing::info!("axum server shutdown");
            axum_result
        }
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!("waiting for shutdown of services (max wait time {max_wait_time_shutdown:?})..");

    match tokio::time::timeout(max_wait_time_shutdown, async move {
        let (axum_result, accountant_result) = tokio::join!(server, accountant_tasks.join());
        axum_result??;
        accountant_result?;
        eyre::Ok(())
    })
    .await
    {
        Ok(Ok(_)) => {
            tracing::info!("successfully finished shutdown in time");
            Ok(())
        }
        Ok(Err(err)) => Err(err),
        Err(_) => {
            eyre::bail!("could not finish shutdown in time");
        }
    }
}

fn main() -> ExitCode {
    // try loading config and unsetting vars before we do any potentially multithreaded work;
    let maybe_config = load_oprf_accountant_config();

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
        world_id_oprf_accountant::metrics::describe_metrics();
        // load the config
        let config = match maybe_config {
            Ok(config) => config,
            Err(err) => {
                tracing::error!(?err, "failed to load config: {err}");
                return ExitCode::FAILURE;
            }
        };

        match run(config).await {
            Ok(_) => {
                tracing::info!("good night");
                ExitCode::SUCCESS
            }
            Err(err) => {
                tracing::error!(?err, "oprf-accountant did shutdown: {err:?}");
                tracing::error!("good night anyways");
                ExitCode::FAILURE
            }
        }
    })
}
