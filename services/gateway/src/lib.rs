pub use crate::config::GatewayConfig;
use crate::{routes::build_app, types::AppState};
use request_tracker::RequestTracker;
use std::{backtrace::Backtrace, net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

mod batcher;
mod config;
mod create_batcher;
mod error;
mod metrics;
mod ops_batcher;
mod request;
mod request_tracker;
mod routes;
mod types;

// Re-export common types
pub use crate::error::{GatewayError, GatewayResult};
pub use ::common::{ProviderArgs, SignerArgs, SignerConfig};

#[derive(Debug)]
pub struct GatewayHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<GatewayResult<()>>,
    pub listen_addr: SocketAddr,
}

impl GatewayHandle {
    pub async fn shutdown(mut self) -> GatewayResult<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Wait for server task to finish
        self.join.await??;
        Ok(())
    }
}

/// For tests only: spawn the gateway server and return a handle with shutdown.
pub async fn spawn_gateway_for_tests(cfg: GatewayConfig) -> GatewayResult<GatewayHandle> {
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

    let listener = tokio::net::TcpListener::bind(cfg.listen_addr)
        .await
        .map_err(|source| GatewayError::Bind {
            source,
            backtrace: Backtrace::capture().to_string(),
        })?;
    let addr = listener
        .local_addr()
        .map_err(|source| GatewayError::ListenerAddr {
            source,
            backtrace: Backtrace::capture().to_string(),
        })?;

    let (tx, rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = rx.await;
    });
    let join = tokio::spawn(async move {
        server.await.map_err(|e| GatewayError::Serve {
            source: e,
            backtrace: Backtrace::capture().to_string(),
        })
    });
    Ok(GatewayHandle {
        shutdown: Some(tx),
        join,
        listen_addr: addr,
    })
}

// Public API: run to completion (blocking future) using env vars (bin-compatible)
pub async fn run() -> GatewayResult<()> {
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
    let listener = tokio::net::TcpListener::bind(cfg.listen_addr)
        .await
        .map_err(|source| GatewayError::Bind {
            source,
            backtrace: Backtrace::capture().to_string(),
        })?;
    tracing::info!("HTTP server listening on {}", cfg.listen_addr);
    axum::serve(listener, app)
        .await
        .map_err(|e| GatewayError::Serve {
            source: e,
            backtrace: Backtrace::capture().to_string(),
        })?;
    Ok(())
}
