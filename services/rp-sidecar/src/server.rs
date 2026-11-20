//! Startup, shared state and shutdown.

use std::{num::NonZeroUsize, sync::Arc, thread};

use eyre::WrapErr as _;
use tokio::{net::TcpListener, sync::Semaphore};
use world_id_proof::artifacts::{
    ZkArtifactSource, ZkArtifactSourceExt as _, embedded::EmbeddedZkArtifacts,
};
use world_id_rp::embedding_similarity::EmbeddingSimilarityPolicy;
use world_id_services_common::ProviderArgs;

use crate::{Config, policy, registries::OnchainRegistries, routes::router};

/// Serves the sidecar until SIGTERM or Ctrl-C, then finishes in-flight requests.
///
/// # Errors
/// The policy, the verification artifacts or the RPC provider cannot be loaded, or the listener
/// cannot be bound.
pub async fn run(config: Config) -> eyre::Result<()> {
    if !config.listen_addr.ip().is_loopback() {
        tracing::warn!(
            listen_addr = %config.listen_addr,
            "listening beyond loopback, but the sidecar has no authentication"
        );
    }

    let policy = policy::load(&config.policy_path)?;
    let artifacts = load_artifacts()?;
    let provider = ProviderArgs {
        http: config.rpc_urls,
        retry: config.rpc_retry,
        ..ProviderArgs::default()
    }
    .http()
    .await?;
    let registries = OnchainRegistries::new(
        provider,
        config.world_id_registry,
        config.credential_schema_issuer_registry,
    );
    let max_concurrent_verifications = config
        .max_concurrent_verifications
        .unwrap_or_else(|| thread::available_parallelism().unwrap_or(NonZeroUsize::MIN));

    let state = AppState::new(policy, registries, artifacts, max_concurrent_verifications);
    let app = router(state, config.request_timeout_secs, config.max_body_bytes);
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .wrap_err_with(|| format!("failed to bind {}", config.listen_addr))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .wrap_err("server failed")
}

/// What the routes verify proofs with.
pub struct AppState<A, R> {
    pub policy: EmbeddingSimilarityPolicy<A>,
    pub registries: R,
    pub artifacts: Arc<dyn ZkArtifactSource>,
    /// One permit per proof verification that may run at once.
    pub proof_verifications: Arc<Semaphore>,
}

impl<A, R> AppState<A, R> {
    /// Verifies proofs under `policy`, against `registries`, with the verifier from `artifacts`,
    /// running at most `max_concurrent_verifications` proof verifications at once.
    pub fn new(
        policy: EmbeddingSimilarityPolicy<A>,
        registries: R,
        artifacts: Arc<dyn ZkArtifactSource>,
        max_concurrent_verifications: NonZeroUsize,
    ) -> Self {
        Self {
            policy,
            registries,
            artifacts,
            proof_verifications: Arc::new(Semaphore::new(max_concurrent_verifications.get())),
        }
    }
}

/// The embedded embedding-similarity verifier, loaded once so a broken artifact fails startup
/// rather than the first verification.
fn load_artifacts() -> eyre::Result<Arc<dyn ZkArtifactSource>> {
    let artifacts = EmbeddedZkArtifacts.cached();
    artifacts
        .embedding_similarity_verifier()
        .wrap_err("failed to load the embedding similarity verifier")?;
    Ok(Arc::new(artifacts))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
