pub use crate::{
    config::{
        BatchPolicyConfig, BatcherConfig, GatewayConfig, OrphanSweeperConfig, RateLimitConfig,
        defaults,
    },
    orphan_sweeper::sweep_once,
    request_tracker::{RequestRecord, RequestTracker, now_unix_secs},
};
use crate::{nonce::RedisNonceManager, routes::build_app, types::AppState};
use redis::aio::ConnectionManager;
use std::{backtrace::Backtrace, net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

mod batch_policy;
mod batcher;
mod config;
mod create_batcher;
mod error;
mod metrics;
pub mod nonce;
mod ops_batcher;
pub mod orphan_sweeper;
mod policy_batcher;
mod request;
pub mod request_tracker;
mod routes;
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

/// For tests only: spawn the gateway server and return a handle with shutdown.
pub async fn spawn_gateway_for_tests(cfg: GatewayConfig) -> GatewayResult<GatewayHandle> {
    let batcher_config = cfg.batcher();
    let rate_limit = cfg.rate_limit();
    let sweeper_config = cfg.sweeper();

    // Each test gateway gets a unique Redis key prefix so that concurrent
    // tests (each backed by a separate Anvil chain) do not share nonce state.
    let redis_client = redis::Client::open(cfg.redis_url.as_str()).expect("invalid REDIS_URL");
    let redis_conn = ConnectionManager::new(redis_client)
        .await
        .expect("failed to connect to Redis for nonce manager");
    let test_prefix = format!(
        "gateway:nonce:test:{}",
        uuid::Uuid::new_v4().as_hyphenated()
    );
    let nonce_mgr = RedisNonceManager::with_prefix(redis_conn, test_prefix);

    let provider = Arc::new(cfg.provider.http_with_nonce_manager(nonce_mgr).await?);
    let registry = Arc::new(WorldIdRegistryInstance::new(
        cfg.registry_addr,
        provider.clone(),
    ));
    let app = build_app(
        registry,
        batcher_config,
        cfg.redis_url,
        rate_limit,
        cfg.request_timeout_secs,
        sweeper_config,
        cfg.batch_policy.clone(),
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

    // Use Redis-backed nonce manager so multiple replicas sharing the same
    // signer key never collide on nonces.  The existing REDIS_URL config
    // value is reused — no new configuration required.
    let redis_client = redis::Client::open(cfg.redis_url.as_str()).map_err(|source| {
        GatewayError::RedisNonceManager {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    })?;
    let redis_conn = ConnectionManager::new(redis_client)
        .await
        .map_err(|source| GatewayError::RedisNonceManager {
            source,
            backtrace: Backtrace::capture().to_string(),
        })?;
    let nonce_mgr = RedisNonceManager::new(redis_conn);
    tracing::info!("Redis-backed nonce manager initialised");

    let batcher_config = cfg.batcher();
    let rate_limit = cfg.rate_limit();
    let sweeper_config = cfg.sweeper();

    let provider = Arc::new(cfg.provider.http_with_nonce_manager(nonce_mgr).await?);
    let registry = Arc::new(WorldIdRegistryInstance::new(cfg.registry_addr, provider));

    tracing::info!("Config is ready. Building app...");
    let app = build_app(
        registry,
        batcher_config,
        cfg.redis_url,
        rate_limit,
        cfg.request_timeout_secs,
        sweeper_config,
        cfg.batch_policy.clone(),
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
