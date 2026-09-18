#![recursion_limit = "256"]

pub use crate::{
    config::{
        BatchPolicyConfig, BatcherConfig, GatewayConfig, OrphanSweeperConfig, RateLimitConfig,
        RegistryVersion, WalletArgs, WalletConfig, defaults,
    },
    orphan_sweeper::sweep_once,
    request_tracker::{RequestRecord, RequestTracker, now_unix_secs},
};
use crate::{routes::build_app, types::AppState};
use std::{backtrace::Backtrace, net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

mod batch_policy;
mod batch_type;
mod batcher;
mod config;
mod error;
pub mod metrics;
pub mod orphan_sweeper;
mod request;
pub mod request_tracker;
mod routes;
mod storage;
mod transaction_submitter;
mod types;

// Re-export common types
pub use crate::error::{GatewayError, GatewayResult};
pub use world_id_services_common::{ProviderArgs, SignerArgs, SignerConfig};

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

/// Builds one read-only provider per configured RPC URL.
///
/// A resolver pass is pinned to a single endpoint, because the shared provider
/// layer fans every call out across all of them and a receipt, a block and a
/// nonce answered by different nodes cannot be reasoned about together.
async fn resolver_providers(
    cfg: &GatewayConfig,
) -> GatewayResult<Vec<alloy::providers::DynProvider>> {
    let mut providers = Vec::with_capacity(cfg.provider.http.len());
    for url in cfg.provider.http.clone() {
        let args = ProviderArgs {
            http: vec![url],
            signer: SignerArgs::default(),
            ..cfg.provider.clone()
        };
        providers.push(args.http().await?);
    }
    Ok(providers)
}

/// For tests only: spawn the gateway server and return a handle with shutdown.
pub async fn spawn_gateway_for_tests(cfg: GatewayConfig) -> GatewayResult<GatewayHandle> {
    let batcher_config = cfg.batcher();
    let rate_limit = cfg.rate_limit();
    let sweeper_config = cfg.sweeper();
    let wallet_config = cfg.wallet()?;

    let wallets = cfg.provider.clone().http_wallets().await?;
    let providers = resolver_providers(&cfg).await?;
    let provider = Arc::new(wallets[0].provider.clone());
    let registry = Arc::new(WorldIdRegistryInstance::new(cfg.registry_addr, provider));
    let app = build_app(
        registry,
        wallets,
        providers,
        cfg.registry_version,
        batcher_config,
        cfg.redis_url,
        rate_limit,
        cfg.request_timeout_secs,
        sweeper_config,
        cfg.batch_policy.clone(),
        wallet_config,
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
    let cfg = GatewayConfig::from_env()?;

    let batcher_config = cfg.batcher();
    let rate_limit = cfg.rate_limit();
    let sweeper_config = cfg.sweeper();
    let wallet_config = cfg.wallet()?;

    let wallets = cfg.provider.clone().http_wallets().await?;
    let providers = resolver_providers(&cfg).await?;
    let provider = Arc::new(wallets[0].provider.clone());
    let registry = Arc::new(WorldIdRegistryInstance::new(cfg.registry_addr, provider));

    tracing::info!(
        registry_version = ?cfg.registry_version,
        wallets = wallets.len(),
        "Config is ready. Building app..."
    );
    let app = build_app(
        registry,
        wallets,
        providers,
        cfg.registry_version,
        batcher_config,
        cfg.redis_url,
        rate_limit,
        cfg.request_timeout_secs,
        sweeper_config,
        cfg.batch_policy.clone(),
        wallet_config,
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
