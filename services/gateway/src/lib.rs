#![recursion_limit = "256"]

use crate::app::{build_gateway, serve_gateway};
pub use crate::{
    config::{
        BatchPolicyConfig, BatcherConfig, GatewayConfig, OrphanSweeperConfig, RateLimitConfig,
        RegistryVersion, defaults,
    },
    transaction_submitter::{RequestRecord, now_unix_secs},
};
use std::{backtrace::Backtrace, net::SocketAddr};
use tokio::sync::oneshot;

mod app;
mod batch_policy;
mod batch_type;
mod batcher;
mod config;
mod error;
pub mod metrics;
mod request;
mod routes;
mod storage;
mod transaction_submitter;
mod types;

// Re-export common types
pub use crate::error::{GatewayError, GatewayResult};
pub use app::Gateway;
pub use world_id_services_common::{ProviderArgs, SignerArgs};

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
    let gateway = build_gateway(cfg).await?;

    let (tx, rx) = oneshot::channel::<()>();
    let join = tokio::spawn(serve_gateway(gateway, listener, async move {
        let _ = rx.await;
    }));
    Ok(GatewayHandle {
        shutdown: Some(tx),
        join,
        listen_addr: addr,
    })
}

// Public API: run to completion (blocking future) using env vars (bin-compatible)
pub async fn run() -> GatewayResult<()> {
    let cfg = GatewayConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(cfg.listen_addr)
        .await
        .map_err(|source| GatewayError::Bind {
            source,
            backtrace: Backtrace::capture().to_string(),
        })?;
    tracing::info!(
        registry_version = ?cfg.registry_version,
        "Config is ready. Building gateway..."
    );
    tracing::info!("HTTP server listening on {}", cfg.listen_addr);
    let gateway = build_gateway(cfg).await?;
    serve_gateway(gateway, listener, std::future::pending()).await
}
