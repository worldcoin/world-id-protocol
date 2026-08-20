use std::{
    future::{Future, IntoFuture},
    sync::Arc,
    time::Duration,
};

use alloy::{primitives::U256, providers::DynProvider};
use moka::future::Cache;
use tokio::task::JoinSet;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;
use world_id_services_common::ProviderWallet;

use crate::{
    batch_policy::{BaseFeeCache, run_base_fee_sampler},
    batcher::{Batcher, CreateBatcher, OpsBatcher},
    config::GatewayConfig,
    error::{GatewayError, GatewayResult},
    routes,
    transaction_submitter::TransactionSubmitter,
    types::{AppState, RootExpiry},
};

const ROOT_CACHE_SIZE: u64 = 1024;
const CREATE_BATCHER_CHANNEL_CAPACITY: usize = 1024;
const OPS_BATCHER_CHANNEL_CAPACITY: usize = 2048;

type Registry = WorldIdRegistryInstance<Arc<DynProvider>>;

/// Components and configuration shared by the gateway service.
// TODO: Some of these components should be abstracted away behind traits
pub struct Gateway {
    pub(crate) config: GatewayConfig,
    pub(crate) registry: Arc<Registry>,
    pub(crate) submitter: Arc<TransactionSubmitter>,
    pub(crate) batcher: Batcher,
    pub(crate) root_cache: Cache<U256, U256>,
    base_fee_cache: BaseFeeCache,
}

impl Gateway {
    /// Build the gateway runtime without constructing routes or starting a server.
    pub(crate) async fn new(
        config: GatewayConfig,
        registry: Arc<Registry>,
        wallets: Vec<ProviderWallet>,
    ) -> GatewayResult<Self> {
        let batch_policy_config = config.batch_policy.clone();
        let submitter = TransactionSubmitter::connect(
            *registry.address(),
            wallets,
            &config.redis_url,
            config.rate_limit.clone(),
            Duration::from_secs(config.transaction_tracker_interval_secs),
            Duration::from_secs(config.stale_submitted_threshold_secs),
        )
        .await?;

        let base_fee_cache = BaseFeeCache::default();

        let create_batcher = Arc::new(CreateBatcher::new(
            registry.clone(),
            submitter.clone(),
            config.max_create_batch_size,
            CREATE_BATCHER_CHANNEL_CAPACITY,
            batch_policy_config.clone(),
            base_fee_cache.clone(),
        ));
        let ops_batcher = Arc::new(OpsBatcher::new(
            registry.clone(),
            submitter.clone(),
            config.max_ops_batch_size,
            OPS_BATCHER_CHANNEL_CAPACITY,
            batch_policy_config,
            base_fee_cache.clone(),
        ));

        Ok(Self {
            config,
            registry,
            submitter,
            batcher: Batcher {
                create: create_batcher,
                ops: ops_batcher,
            },
            root_cache: Cache::builder()
                .max_capacity(ROOT_CACHE_SIZE)
                .expire_after(RootExpiry)
                .build(),
            base_fee_cache,
        })
    }
}

pub(crate) async fn build_gateway(config: GatewayConfig) -> GatewayResult<Gateway> {
    let wallets = config.provider.clone().http_wallets().await?;
    let provider = Arc::new(wallets[0].provider.clone());
    let registry = Arc::new(WorldIdRegistryInstance::new(config.registry_addr, provider));
    Gateway::new(config, registry, wallets).await
}

fn start_tasks(gateway: Arc<Gateway>) -> JoinSet<&'static str> {
    let mut tasks = JoinSet::new();

    let task_gateway = gateway.clone();
    tasks.spawn(async move {
        task_gateway.submitter.clone().run_tracker().await;
        "transaction tracker"
    });

    let task_gateway = gateway.clone();
    tasks.spawn(async move {
        let provider = task_gateway.registry.provider().clone();
        let interval = Duration::from_millis(task_gateway.config.batch_policy.reeval_ms);
        let cache = task_gateway.base_fee_cache.clone();
        run_base_fee_sampler(provider, interval, cache).await;
        "base fee sampler"
    });

    let task_gateway = gateway.clone();
    tasks.spawn(async move {
        task_gateway.batcher.create.run().await;
        "create batcher"
    });

    let task_gateway = gateway;
    tasks.spawn(async move {
        task_gateway.batcher.ops.run().await;
        "ops batcher"
    });

    tasks
}

/// Set up the gateway routes, run the HTTP server, and supervise background tasks.
pub(crate) async fn serve_gateway<F>(
    gateway: Gateway,
    listener: tokio::net::TcpListener,
    shutdown: F,
) -> GatewayResult<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let state: AppState = Arc::new(gateway);
    let mut tasks = start_tasks(state.clone());
    tracing::info!("Gateway background tasks started");

    let app = routes::router(state.clone());
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .into_future();

    let result = supervise(server, &mut tasks).await;

    tasks.shutdown().await;
    result
}

async fn supervise<F>(server: F, tasks: &mut JoinSet<&'static str>) -> GatewayResult<()>
where
    F: Future<Output = std::io::Result<()>>,
{
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => result.map_err(|source| GatewayError::Serve {
            source,
            backtrace: std::backtrace::Backtrace::capture().to_string(),
        }),
        task = tasks.join_next() => match task {
            Some(Ok(task)) => Err(GatewayError::BackgroundTaskExited(task)),
            Some(Err(error)) => Err(error.into()),
            None => Err(GatewayError::BackgroundTaskExited("task supervisor")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn supervisor_reports_background_task_exit() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async { "test task" });

        let error = supervise(std::future::pending(), &mut tasks)
            .await
            .expect_err("task exit should stop the gateway");

        assert!(matches!(
            error,
            GatewayError::BackgroundTaskExited("test task")
        ));
    }

    #[tokio::test]
    async fn supervisor_reports_background_task_panic() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {
            panic!("test task panic");
            #[allow(unreachable_code)]
            "test task"
        });

        let error = supervise(std::future::pending(), &mut tasks)
            .await
            .expect_err("task panic should stop the gateway");

        assert!(matches!(error, GatewayError::Join { source, .. } if source.is_panic()));
    }
}
