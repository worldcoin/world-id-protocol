#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::net::SocketAddr;
use std::sync::Arc;

use alloy::providers::{DynProvider, Provider};
use dotenvy as _;
use metrics_exporter_prometheus as _;
use opentelemetry as _;
use opentelemetry_otlp as _;
use opentelemetry_sdk as _;
use tokio::sync::oneshot;
use tracing_subscriber as _;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

use crate::routes::build_app;

mod batcher;
mod config;
mod create_batcher;
mod request_tracker;
mod routes;
mod types;

pub use crate::config::GatewayConfig;

// Re-export common types
pub use ::common::{ProviderArgs, SignerArgs, SignerConfig};

#[derive(Debug)]
pub struct GatewayHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
    pub listen_addr: SocketAddr,
}

impl GatewayHandle {
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Wait for server task to finish
        match self.join.await {
            Ok(res) => res,
            Err(e) => Err(anyhow::anyhow!(format!("join error: {e}"))),
        }
    }
}

/// For tests only: spawn the gateway server and return a handle with shutdown.
pub async fn spawn_gateway_for_tests(cfg: GatewayConfig) -> anyhow::Result<GatewayHandle> {
    // Install metrics recorder if configured
    if let Some(metrics_addr) = cfg.metrics.addr {
        install_metrics_recorder(metrics_addr)?;
    }

    // Install OTLP exporter if configured
    if let Some(ref otlp_endpoint) = cfg.metrics.otlp_endpoint {
        install_otlp_exporter(otlp_endpoint, &cfg.metrics.service_name)?;
    }

    let provider = Arc::new(cfg.provider.http().await?);
    // Create registry with type-erased provider for use in routes
    let dyn_provider: Arc<DynProvider> = Arc::new(provider.clone().erased());
    let registry = Arc::new(WorldIdRegistryInstance::new(
        cfg.registry_addr,
        dyn_provider.clone(),
    ));

    let app = build_app(
        dyn_provider,
        registry,
        cfg.batch_ms,
        cfg.max_create_batch_size,
        cfg.redis_url,
        cfg.metrics.is_enabled(),
    )
    .await?;

    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    let addr = listener.local_addr()?;

    let (tx, rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = rx.await;
    });
    let join = tokio::spawn(async move { server.await.map_err(|e| anyhow::anyhow!(e)) });
    Ok(GatewayHandle {
        shutdown: Some(tx),
        join,
        listen_addr: addr,
    })
}

/// Install Prometheus metrics recorder if metrics_addr is configured.
fn install_metrics_recorder(metrics_addr: SocketAddr) -> anyhow::Result<()> {
    use metrics_exporter_prometheus::PrometheusBuilder;

    let builder = PrometheusBuilder::new().with_http_listener(metrics_addr);
    builder
        .install()
        .map_err(|e| anyhow::anyhow!("failed to install metrics recorder: {e}"))?;

    tracing::info!(addr = %metrics_addr, "metrics endpoint enabled");
    Ok(())
}

/// Install OTLP metrics exporter if otlp_endpoint is configured.
fn install_otlp_exporter(endpoint: &str, service_name: &str) -> anyhow::Result<()> {
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::metrics::reader::DefaultAggregationSelector;
    use opentelemetry_sdk::metrics::reader::DefaultTemporalitySelector;
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
    use opentelemetry_sdk::Resource;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint)
        .build_metrics_exporter(
            Box::new(DefaultAggregationSelector::new()),
            Box::new(DefaultTemporalitySelector::new()),
        )
        .map_err(|e| anyhow::anyhow!("failed to build OTLP exporter: {e}"))?;

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(Resource::new([KeyValue::new(
            "service.name",
            service_name.to_string(),
        )]))
        .build();

    opentelemetry::global::set_meter_provider(provider);

    tracing::info!(endpoint = %endpoint, service_name = %service_name, "OTLP metrics exporter enabled");
    Ok(())
}

// Public API: run to completion (blocking future) using env vars (bin-compatible)
pub async fn run() -> anyhow::Result<()> {
    let cfg = GatewayConfig::from_env();

    // Install metrics recorder if configured
    if let Some(metrics_addr) = cfg.metrics.addr {
        install_metrics_recorder(metrics_addr)?;
    }

    // Install OTLP exporter if configured
    if let Some(ref otlp_endpoint) = cfg.metrics.otlp_endpoint {
        install_otlp_exporter(otlp_endpoint, &cfg.metrics.service_name)?;
    }

    let provider = Arc::new(cfg.provider.http().await?);
    // Create registry with type-erased provider
    let dyn_provider: Arc<DynProvider> = Arc::new(provider.clone().erased());
    let registry = Arc::new(WorldIdRegistryInstance::new(
        cfg.registry_addr,
        dyn_provider.clone(),
    ));

    let app = build_app(
        dyn_provider,
        registry,
        cfg.batch_ms,
        cfg.max_create_batch_size,
        cfg.redis_url,
        cfg.metrics.is_enabled(),
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
