//! Startup, shared state and shutdown.

use std::{num::NonZeroUsize, sync::Arc, thread, time::Duration};

use eyre::WrapErr as _;
use tokio::{net::TcpListener, sync::Semaphore};
use world_id_proof::artifacts::{
    ZkArtifactSource, ZkArtifactSourceExt as _, embedded::EmbeddedZkArtifacts,
};
use world_id_rp::embedding_similarity::EmbeddingSimilarityPolicy;

use crate::{config::Config, policy, registries::OnchainRegistries, routes::router};

/// Serves the sidecar until SIGTERM or Ctrl-C, then finishes in-flight requests and waits up to
/// the request timeout for verifications whose callers hung up.
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

    let policy = policy::load(&config.policy_path).wrap_err_with(|| {
        format!(
            "failed to load the policy at {}",
            config.policy_path.display()
        )
    })?;
    let artifacts = load_artifacts()?;
    let registries = OnchainRegistries::connect(
        &config.rpc_urls,
        config.rpc_retry(),
        config.world_id_registry,
        config.credential_schema_issuer_registry,
    )
    .await?;
    let max_concurrent_verifications = config.max_concurrent_verifications.unwrap_or_else(|| {
        thread::available_parallelism().unwrap_or_else(|error| {
            tracing::warn!(%error, "cannot count the CPUs, so only one verification runs at once");
            NonZeroUsize::MIN
        })
    });

    let state = AppState::new(
        policy,
        registries,
        artifacts,
        max_concurrent_verifications,
        config.request_timeout(),
    );
    let slots = Arc::clone(&state.verification_slots);
    let app = router(state, config.max_body_bytes);
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .wrap_err_with(|| format!("failed to bind {}", config.listen_addr))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .wrap_err("server failed")?;

    // Let verifications whose callers hung up finish before the runtime and its timers go away.
    let all_slots = u32::try_from(max_concurrent_verifications.get()).unwrap_or(u32::MAX);
    let drain = tokio::time::timeout(config.request_timeout(), slots.acquire_many(all_slots));
    if drain.await.is_err() {
        tracing::warn!("verifications are still running at shutdown; waiting for their CPU work");
    }
    Ok(())
}

/// What the routes verify proofs with.
pub struct AppState<A, R> {
    /// What the RP accepts beyond its own request.
    pub policy: EmbeddingSimilarityPolicy<A>,
    /// Where roots and Issuer keys are checked.
    pub registries: R,
    /// The embedding-similarity verifier.
    pub artifacts: Arc<dyn ZkArtifactSource>,
    /// One permit per verification that may run at once, each on its own blocking thread.
    pub verification_slots: Arc<Semaphore>,
    /// How long one verification may take.
    pub request_timeout: Duration,
}

impl<A, R> AppState<A, R> {
    /// Creates the `max_concurrent_verifications` slots that all requests share.
    pub fn new(
        policy: EmbeddingSimilarityPolicy<A>,
        registries: R,
        artifacts: Arc<dyn ZkArtifactSource>,
        max_concurrent_verifications: NonZeroUsize,
        request_timeout: Duration,
    ) -> Self {
        Self {
            policy,
            registries,
            artifacts,
            verification_slots: Arc::new(Semaphore::new(max_concurrent_verifications.get())),
            request_timeout,
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
