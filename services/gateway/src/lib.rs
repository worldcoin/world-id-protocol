use std::net::SocketAddr;
use std::sync::Arc;

use alloy::providers::{DynProvider, Provider, RootProvider};
use alloy::pubsub::PubSubFrontend;

// Type alias for websocket provider (used for type annotation when passing None)
type WsProvider = RootProvider<PubSubFrontend>;
use crate::routes::build_app;
use crate::types::AppState;
use request_tracker::RequestTracker;
use tokio::sync::oneshot;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

// Placeholder type for WS provider when we don't have websocket support.
// This type is never instantiated - we always pass None for ws_provider.
type NoWsProvider = alloy::providers::RootProvider;

mod batcher;
mod config;
mod create_batcher;
mod ops_batcher;
mod request_tracker;
mod routes;
pub mod telemetry;
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
    let provider = Arc::new(cfg.provider.http().await?);
    // Create registry with type-erased provider for use in routes
    let dyn_provider: Arc<DynProvider> = Arc::new(provider.clone().erased());
    let registry = Arc::new(WorldIdRegistryInstance::new(cfg.registry_addr, dyn_provider));

    let ws_provider: Option<Arc<WsProvider>> = None;
    let app = build_app(
        provider,
        ws_provider,
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
    // Create registry with type-erased provider
    let dyn_provider: Arc<DynProvider> = Arc::new(provider.clone().erased());
    let registry = Arc::new(WorldIdRegistryInstance::new(cfg.registry_addr, dyn_provider));

    tracing::info!("Config is ready. Building app...");
    let app = build_app(
        provider,
        None,
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
