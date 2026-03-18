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
mod error;
pub mod metrics;
pub mod nonce;
pub mod orphan_sweeper;
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
    /// The Redis key prefix used by this gateway's RequestTracker.
    /// Empty string in production; set to a per-instance UUID in test gateways.
    /// Tests can use this to construct the correct prefixed Redis key names
    /// when asserting on in-flight lock keys directly.
    pub redis_key_prefix: String,
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

    // Each test gateway gets a per-instance UUID so that concurrent test
    // processes (nextest runs every test in its own OS process) never share
    // Redis state, even when they use the same server and DB.
    let instance_uuid = uuid::Uuid::new_v4().as_hyphenated().to_string();

    let redis_client = redis::Client::open(cfg.redis_url.as_str()).expect("invalid REDIS_URL");
    let redis_conn = ConnectionManager::new(redis_client)
        .await
        .expect("failed to connect to Redis for nonce manager");
    let nonce_prefix = format!("test:{instance_uuid}:gateway:nonce:");
    let nonce_mgr = RedisNonceManager::with_prefix(redis_conn, nonce_prefix);

    let provider = Arc::new(cfg.provider.http_with_nonce_manager(nonce_mgr).await?);
    let registry = Arc::new(WorldIdRegistryInstance::new(
        cfg.registry_addr,
        provider.clone(),
    ));

    // Tracker key prefix: "test:<uuid>:".  Every gateway:request:*, gateway:inflight:*
    // and gateway:pending_requests key will be scoped under this prefix.
    let tracker_key_prefix = format!("test:{instance_uuid}:");
    let app = build_app(
        registry,
        batcher_config,
        cfg.redis_url,
        rate_limit,
        cfg.request_timeout_secs,
        sweeper_config,
        cfg.batch_policy.clone(),
        Some(tracker_key_prefix.clone()),
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
        redis_key_prefix: tracker_key_prefix,
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
        None, // no prefix in production
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
