#![cfg_attr(not(test), warn(unused_crate_dependencies))]
use dotenvy as _;
use tracing_subscriber as _;

use std::net::SocketAddr;
use std::sync::Arc;

pub use crate::config::{GatewayConfig};
use crate::{routes::build_app, types::AppState};
use tokio::sync::oneshot;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

mod batcher;
mod config;
mod request;
mod routes;
mod types;
mod request_tracker;


// Re-export common types
pub use ::common::{ProviderArgs, SignerArgs, SignerConfig};
pub use request_tracker::{RequestTracker};

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
    let provider = Arc::new(cfg.provider.http().await?);
    let registry = Arc::new(WorldIdRegistryInstance::new(
        cfg.registry_addr,
        provider.clone(),
    ));

    let app = build_app(
        registry,
        cfg.batch_ms,
        cfg.max_create_batch_size,
        cfg.max_ops_batch_size,
        cfg.redis_url,
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

// Public API: run to completion (blocking future) using env vars (bin-compatible)
pub async fn run() -> anyhow::Result<()> {
    let cfg = GatewayConfig::from_env();
    let provider = Arc::new(cfg.provider.http().await?);
    let registry = Arc::new(WorldIdRegistryInstance::new(
        cfg.registry_addr,
        provider.clone(),
    ));

    tracing::info!("Config is ready. Building app...");
    let app = build_app(
        registry,
        cfg.batch_ms,
        cfg.max_create_batch_size,
        cfg.max_ops_batch_size,
        cfg.redis_url,
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    tracing::info!("HTTP server listening on {}", cfg.listen_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
