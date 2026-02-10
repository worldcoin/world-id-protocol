use crate::{
    blockchain::{Blockchain, BlockchainEvent, RegistryEvent},
    config::{AppState, HttpConfig, IndexerConfig, RunMode},
    db::DB,
    events_committer::EventsCommitter,
};
use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::Log,
};
use futures_util::StreamExt;
use std::{backtrace::Backtrace, net::SocketAddr, sync::Arc, time::Duration};
use tracing::instrument;
use world_id_core::world_id_registry::WorldIdRegistry;

// re-exports
pub use config::GlobalConfig;
pub use error::{IndexerError, IndexerResult};

pub mod blockchain;
pub mod config;
pub mod db;
mod error;
pub mod events_committer;
mod routes;
mod sanity_check;
mod tree;

#[instrument(level = "info", skip_all)]
async unsafe fn initialize_tree_with_config(
    tree_cache_cfg: &config::TreeCacheConfig,
    db: &DB,
) -> eyre::Result<tree::TreeState> {
    let cache_path = std::path::Path::new(&tree_cache_cfg.cache_file_path);

    let tree_state =
        unsafe { tree::cached_tree::init_tree(db, cache_path, tree_cache_cfg.tree_depth).await? };

    let root = tree_state.root().await;
    tracing::info!(
        root = %format!("0x{:x}", root),
        depth = tree_cache_cfg.tree_depth,
        "Tree initialized successfully"
    );

    Ok(tree_state)
}

/// Background task: periodically sync the in-memory tree with DB events.
/// Used in HttpOnly mode (where an external indexer writes to DB).
#[instrument(level = "info", skip_all, fields(interval_secs))]
async fn tree_sync_loop(
    db: DB,
    interval_secs: u64,
    tree_state: tree::TreeState,
) -> IndexerResult<()> {
    tracing::info!(interval_secs, "Starting tree sync loop");

    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        match tree::cached_tree::sync_from_db(&db, &tree_state).await {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count, "Synced events from DB to tree");
                }
            }
            Err(e) => {
                tracing::error!(?e, "Failed to sync tree from DB");
            }
        }
    }
}

#[instrument(level = "info", skip_all, fields(%addr))]
async fn start_http_server(
    rpc_url: &str,
    registry_address: Address,
    addr: SocketAddr,
    db: DB,
    tree_state: tree::TreeState,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().expect("invalid RPC URL"));
    let registry = WorldIdRegistry::new(registry_address, provider.erased());
    let router = routes::handler(AppState::new(db, Arc::new(registry), tree_state));
    tracing::info!(%addr, "HTTP server listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| IndexerError::Bind {
            source,
            backtrace: Backtrace::capture().to_string(),
        })?;
    axum::serve(listener, router)
        .await
        .map_err(|source| IndexerError::Serve {
            source,
            backtrace: Backtrace::capture().to_string(),
        })?;
    Ok(())
}

#[instrument(level = "info", skip_all)]
pub async unsafe fn run_indexer(cfg: GlobalConfig) -> eyre::Result<()> {
    tracing::info!("Creating DB...");
    let db = DB::new(&cfg.db_url, None).await?;
    db.run_migrations().await?;
    tracing::info!("🟢 DB successfully created .");

    match cfg.run_mode {
        RunMode::IndexerOnly { indexer_config } => {
            tracing::info!("Running in INDEXER-ONLY mode (no in-memory tree)");

            tracing::info!("Connecting to blockchain...");
            let blockchain =
                Blockchain::new(&cfg.http_rpc_url, &cfg.ws_rpc_url, cfg.registry_address).await?;
            tracing::info!("Connection to blockchain successful.");

            run_indexer_only(&blockchain, db, indexer_config).await
        }
        RunMode::HttpOnly { http_config } => {
            tracing::info!("Running in HTTP-ONLY mode (initializing tree with cache)");
            let start_time = std::time::Instant::now();
            let tree_cache_cfg = http_config.tree_cache.clone();
            let tree_state = unsafe { initialize_tree_with_config(&tree_cache_cfg, &db).await? };
            tracing::info!("tree initialization took {:?}", start_time.elapsed());

            run_http_only(
                db,
                &cfg.http_rpc_url,
                cfg.registry_address,
                http_config,
                tree_state,
            )
            .await
        }
        RunMode::Both {
            indexer_config,
            http_config,
        } => {
            tracing::info!("Running in BOTH mode (indexer + HTTP server)");

            tracing::info!("Connecting to blockchain...");
            let blockchain =
                Blockchain::new(&cfg.http_rpc_url, &cfg.ws_rpc_url, cfg.registry_address).await?;
            tracing::info!("Connection to blockchain successful.");

            run_both(
                &blockchain,
                db,
                &cfg.http_rpc_url,
                cfg.registry_address,
                indexer_config,
                http_config,
            )
            .await
        }
    }
}

#[instrument(level = "info", skip_all)]
async fn run_indexer_only(
    blockchain: &Blockchain,
    db: DB,
    indexer_cfg: IndexerConfig,
) -> eyre::Result<()> {
    let from = match db.world_tree_events().get_latest_block().await? {
        Some(block) => block,
        None => indexer_cfg.start_block,
    };

    tracing::info!("switching to websocket live follow");
    stream_logs(blockchain, &db, from, None).await?;

    Ok(())
}

#[instrument(level = "info", skip_all)]
async fn run_http_only(
    db: DB,
    rpc_url: &str,
    registry_address: Address,
    http_cfg: HttpConfig,
    tree_state: tree::TreeState,
) -> eyre::Result<()> {
    // Start tree sync loop
    let sync_pool = db.clone();
    let sync_interval = http_cfg.db_poll_interval_secs;
    let sync_tree_state = tree_state.clone();
    let sync_handle = tokio::spawn(async move {
        if let Err(e) = tree_sync_loop(sync_pool, sync_interval, sync_tree_state).await {
            tracing::error!(?e, "Tree sync loop failed");
        }
    });

    // Start root sanity checker in the background
    let mut sanity_handle = None;
    if let Some(sanity_interval) = http_cfg.sanity_check_interval_secs {
        let rpc_url = rpc_url.to_string();
        let sanity_tree_state = tree_state.clone();
        sanity_handle = Some(tokio::spawn(async move {
            if let Err(e) = sanity_check::root_sanity_check_loop(
                rpc_url,
                registry_address,
                sanity_interval,
                sanity_tree_state,
            )
            .await
            {
                tracing::error!(?e, "Root sanity checker failed");
            }
        }));
    }

    // Start HTTP server
    let http_result = start_http_server(
        rpc_url,
        registry_address,
        http_cfg.http_addr,
        db,
        tree_state,
    )
    .await;

    sync_handle.abort();
    if let Some(handle) = sanity_handle {
        handle.abort();
    }
    http_result
}

#[instrument(level = "info", skip_all)]
async fn run_both(
    blockchain: &Blockchain,
    db: DB,
    rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    http_cfg: HttpConfig,
) -> eyre::Result<()> {
    let tree_cache_cfg = &http_cfg.tree_cache;

    // --- Phase 1: Backfill historical events into DB (no tree) ---
    let from = match db.world_tree_roots().get_latest_block().await? {
        Some(block) => block,
        None => indexer_cfg.start_block,
    };

    tracing::info!(from_block = from, "Phase 1: starting historical backfill");

    let (raw_logs, backfill_up_to_block) = blockchain.get_backfill_events(from).await?;

    tracing::info!(
        log_count = raw_logs.len(),
        backfill_up_to_block,
        "Phase 1: fetched historical logs, processing..."
    );

    let committed_batches = save_events(&db, raw_logs).await?;

    tracing::info!(
        committed_batches,
        "Phase 1: backfill complete, all historical events stored in DB"
    );

    // --- Phase 2: Build tree from complete DB ---
    tracing::info!("Phase 2: building tree from DB");
    let start_time = std::time::Instant::now();
    let tree_state = unsafe { initialize_tree_with_config(tree_cache_cfg, &db).await? };
    tracing::info!(
        "Phase 2: tree initialization took {:?}",
        start_time.elapsed()
    );

    // --- Phase 3: Start HTTP server + sanity check ---
    let http_tree_state = tree_state.clone();
    let sanity_tree_state = tree_state.clone();

    let http_pool = db.clone();
    let http_addr = http_cfg.http_addr;
    let rpc_url_clone = rpc_url.to_string();
    let http_handle = tokio::spawn(async move {
        start_http_server(
            &rpc_url_clone,
            registry_address,
            http_addr,
            http_pool,
            http_tree_state,
        )
        .await
    });

    let mut sanity_handle = None;
    if let Some(sanity_interval) = http_cfg.sanity_check_interval_secs {
        let rpc_url = rpc_url.to_string();
        sanity_handle = Some(tokio::spawn(async move {
            if let Err(e) = sanity_check::root_sanity_check_loop(
                rpc_url,
                registry_address,
                sanity_interval,
                sanity_tree_state,
            )
            .await
            {
                tracing::error!(?e, "Root sanity checker failed");
            }
        }));
    }

    // --- Phase 4: Live event streaming with tree sync ---
    tracing::info!(
        from_block = backfill_up_to_block,
        "Phase 4: starting live event stream with tree sync"
    );

    stream_logs(blockchain, &db, backfill_up_to_block + 1, Some(&tree_state)).await?;

    http_handle.abort();
    if let Some(handle) = sanity_handle {
        handle.abort();
    }
    Ok(())
}

pub async fn handle_registry_event<'a>(
    db: &DB,
    events_committer: &mut EventsCommitter<'a>,
    event: &BlockchainEvent<RegistryEvent>,
    tree_state: Option<&tree::TreeState>,
) -> IndexerResult<()> {
    let committed = events_committer.handle_event(event.clone()).await?;

    // After a DB commit, sync the in-memory tree from DB
    if let Some(tree_state) = tree_state
        && committed
        && let Err(e) = tree::cached_tree::sync_from_db(db, tree_state).await
    {
        tracing::error!(?e, "failed to sync tree from DB after commit");
    }

    Ok(())
}

/// Process backfill logs from HTTP get_logs, writing to DB only (no tree sync).
/// Returns the number of committed batches.
async fn save_events(db: &DB, raw_logs: Vec<Log>) -> IndexerResult<usize> {
    let mut events_committer = EventsCommitter::new(db);
    let mut committed_batches = 0usize;

    for log in raw_logs {
        match RegistryEvent::decode(&log) {
            Ok(event) => {
                tracing::info!(?event, "processing backfill event");
                let committed = events_committer.handle_event(event).await?;
                if committed {
                    committed_batches += 1;
                }
            }
            Err(e) => {
                tracing::warn!(?e, "failed to decode backfill event");
            }
        }
    }

    Ok(committed_batches)
}

#[instrument(level = "info", skip_all, fields(start_from))]
pub async fn stream_logs(
    blockchain: &Blockchain,
    db: &DB,
    start_from: u64,
    tree_state: Option<&tree::TreeState>,
) -> IndexerResult<()> {
    let mut stream = blockchain.stream_world_tree_events(start_from).await?;
    let mut events_committer = EventsCommitter::new(db);

    while let Some(log) = stream.next().await {
        tracing::info!(?log, "processing live registry log");
        match log {
            Ok(event) => {
                tracing::info!(?event, "decoded live registry event");

                if let Err(e) =
                    handle_registry_event(db, &mut events_committer, &event, tree_state).await
                {
                    tracing::error!(?e, ?event, "failed to handle registry event");
                }
            }
            Err(ref e) => {
                tracing::warn!(?e, ?log, "failed to decode live registry event");
            }
        }
    }
    Ok(())
}
