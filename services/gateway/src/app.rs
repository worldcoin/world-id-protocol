use std::{
    future::{Future, IntoFuture},
    panic::AssertUnwindSafe,
    sync::Arc,
    time::Duration,
};

use alloy::{primitives::U256, providers::DynProvider};
use futures::FutureExt as _;
use moka::future::Cache;
use tokio::task::JoinSet;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;
use world_id_services_common::ProviderWallet;

use crate::{
    batch_policy::{BaseFeeCache, run_base_fee_sampler},
    batcher::{Batcher, CreateBatcher, OpsBatcher},
    config::GatewayConfig,
    error::{GatewayError, GatewayResult},
    orphan_sweeper::run_orphan_sweeper,
    request_tracker::RequestTracker,
    routes,
    storage::wallet_store::WalletStore,
    transaction_submitter::TransactionSubmitter,
    types::{AppState, RootExpiry},
};

const ROOT_CACHE_SIZE: u64 = 1024;
const CREATE_BATCHER_CHANNEL_CAPACITY: usize = 1024;
const OPS_BATCHER_CHANNEL_CAPACITY: usize = 2048;

type Registry = WorldIdRegistryInstance<Arc<DynProvider>>;

/// Components and configuration shared by the gateway service.
pub struct Gateway {
    pub(crate) config: GatewayConfig,
    pub(crate) registry: Arc<Registry>,
    pub(crate) submitter: Arc<TransactionSubmitter>,
    pub(crate) tracker: RequestTracker,
    sweeper_wallets: WalletStore,
    sweeper_providers: Vec<DynProvider>,
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
        resolver_providers: Vec<DynProvider>,
    ) -> GatewayResult<Self> {
        let batcher_config = config.batcher();
        let batch_policy_config = config.batch_policy.clone();
        let rate_limit = config.rate_limit();
        let sweeper_config = config.sweeper();
        let wallet_config = config.wallet()?;
        let tracker = RequestTracker::new(
            config.redis_url.clone(),
            rate_limit,
            Duration::from_secs(wallet_config.inflight_ttl_secs(&sweeper_config)),
        )
        .await;
        let sweeper_providers = resolver_providers.clone();
        let submitter = TransactionSubmitter::connect(
            wallets,
            resolver_providers,
            tracker.clone(),
            &config.redis_url,
            wallet_config,
        )
        .await?;
        let sweeper_wallets = WalletStore::connect(&config.redis_url).await?;

        let base_fee_cache = BaseFeeCache::default();

        let create_batcher = Arc::new(CreateBatcher::new(
            registry.clone(),
            submitter.clone(),
            batcher_config.max_create_batch_size,
            CREATE_BATCHER_CHANNEL_CAPACITY,
            batch_policy_config.clone(),
            base_fee_cache.clone(),
        ));
        let ops_batcher = Arc::new(OpsBatcher::new(
            registry.clone(),
            submitter.clone(),
            batcher_config.max_ops_batch_size,
            OPS_BATCHER_CHANNEL_CAPACITY,
            batch_policy_config,
            base_fee_cache.clone(),
        ));

        Ok(Self {
            config,
            registry,
            submitter,
            tracker,
            sweeper_wallets,
            sweeper_providers,
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
    let providers = crate::resolver_providers(&config).await?;
    let provider = Arc::new(wallets[0].provider.clone());
    let registry = Arc::new(WorldIdRegistryInstance::new(config.registry_addr, provider));
    Gateway::new(config, registry, wallets, providers).await
}

fn start_tasks(gateway: Arc<Gateway>) -> JoinSet<&'static str> {
    let mut tasks = JoinSet::new();

    let task_gateway = gateway.clone();
    tasks.spawn(async move {
        supervise_resolver(task_gateway.submitter.clone()).await;
        "transaction resolver"
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

    let task_gateway = gateway.clone();
    tasks.spawn(async move {
        run_orphan_sweeper(
            task_gateway.tracker.clone(),
            task_gateway.sweeper_wallets.clone(),
            task_gateway.sweeper_providers.clone(),
            task_gateway.config.sweeper(),
        )
        .await;
        "orphan sweeper"
    });

    tracing::info!(
        wallets = gateway.submitter.pool_size(),
        acquirable = gateway.submitter.acquirable_size(),
        "Transaction resolver initialized"
    );

    let task_gateway = gateway;
    tasks.spawn(async move {
        task_gateway.batcher.ops.run().await;
        "ops batcher"
    });

    tasks
}

/// Restarts the resolver after an unexpected exit or panic.
///
/// Polling the worker here ties its lifetime to the supervised task.
async fn supervise_resolver(submitter: Arc<TransactionSubmitter>) {
    loop {
        match AssertUnwindSafe(submitter.clone().run_resolver())
            .catch_unwind()
            .await
        {
            Ok(()) => tracing::error!("transaction resolver exited unexpectedly; restarting"),
            Err(_) => tracing::error!("transaction resolver panicked; restarting"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
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
    async fn handle_shutdown_releases_background_tasks() {
        use clap::Parser as _;
        use testcontainers_modules::{
            redis::{REDIS_PORT, Redis},
            testcontainers::{ImageExt as _, runners::AsyncRunner as _},
        };
        use world_id_test_utils::anvil::TestAnvil;

        let anvil = TestAnvil::spawn_auto_mine().expect("failed to spawn Anvil");
        let redis = Redis::default()
            .with_tag("latest")
            .start()
            .await
            .expect("failed to start Redis");
        let redis_url = format!(
            "redis://{}:{}",
            redis.get_host().await.expect("Redis host"),
            redis
                .get_host_port_ipv4(REDIS_PORT)
                .await
                .expect("Redis port"),
        );
        let config = GatewayConfig::try_parse_from([
            "test",
            "--registry-addr",
            "0x0000000000000000000000000000000000000001",
            "--registry-version",
            "v1",
            "--rpc-url",
            anvil.endpoint(),
            "--wallet-private-key",
            // Anvil's public development key.
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "--redis-url",
            &redis_url,
        ])
        .expect("gateway config");
        let gateway = build_gateway(config).await.expect("build gateway");
        let submitter = Arc::downgrade(&gateway.submitter);
        let create_batcher = Arc::downgrade(&gateway.batcher.create);
        let ops_batcher = Arc::downgrade(&gateway.batcher.ops);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway");
        let listen_addr = listener.local_addr().expect("listener address");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(serve_gateway(gateway, listener, async move {
            let _ = rx.await;
        }));
        let handle = crate::GatewayHandle {
            shutdown: Some(tx),
            join,
            listen_addr,
        };
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("HTTP client")
            .get(format!("http://{listen_addr}/health"))
            .send()
            .await
            .expect("gateway serves requests")
            .error_for_status()
            .expect("healthy gateway");

        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .expect("shutdown deadline")
            .expect("gateway shuts down");

        assert!(
            submitter.upgrade().is_none(),
            "resolver retained the submitter"
        );
        assert!(
            create_batcher.upgrade().is_none(),
            "create batcher retained"
        );
        assert!(ops_batcher.upgrade().is_none(), "ops batcher retained");
    }

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
