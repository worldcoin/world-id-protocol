use crate::{
    blockchain::{Blockchain, BlockchainEvent, BlockchainResult, RegistryEvent},
    config::{AppState, HttpConfig, IndexerConfig, RunMode},
    db::DB,
    events_committer::EventsCommitter,
};
use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use futures_util::{Stream, StreamExt};
use std::{
    backtrace::Backtrace,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
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
pub mod tree;

static BLOCKCHAIN_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Initializes the in-memory tree from a cache file if it exists, otherwise builds from DB.
///
/// # Safety
///
/// This function is marked unsafe because it performs memory-mapped file operations for the tree cache.
/// The caller must ensure that the cache file is not concurrently accessed or modified
/// by other processes while the tree is using it.
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

/// Runs the indexer
///
/// # Safety
///
/// This function is marked unsafe because it performs memory-mapped file operations for the tree cache.
/// The caller must ensure that the cache file is not concurrently accessed or modified
/// by other processes while the tree is using it.
#[instrument(level = "info", skip_all)]
pub async unsafe fn run_indexer(cfg: GlobalConfig) -> eyre::Result<()> {
    tracing::info!("Creating DB...");
    let db = DB::new(&cfg.db_url, None).await?;
    db.run_migrations().await?;
    tracing::info!("🟢 DB successfully created .");

    match cfg.run_mode {
        RunMode::IndexerOnly { indexer_config } => {
            tracing::info!("Running in INDEXER-ONLY mode (no in-memory tree)");

            run_indexer_only(
                db,
                &cfg.http_rpc_url,
                &cfg.ws_rpc_url,
                cfg.registry_address,
                indexer_config,
            )
            .await
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

            unsafe {
                run_both(
                    db,
                    &cfg.http_rpc_url,
                    &cfg.ws_rpc_url,
                    cfg.registry_address,
                    indexer_config,
                    http_config,
                )
            }
            .await
        }
    }
}

#[instrument(level = "info", skip_all)]
async fn run_indexer_only(
    db: DB,
    http_rpc_url: &str,
    ws_rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
) -> eyre::Result<()> {
    process_registry_events(
        http_rpc_url,
        ws_rpc_url,
        registry_address,
        indexer_cfg,
        &db,
        None,
    )
    .await?;

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

/// Runs both the indexer and HTTP server in the same process, sharing the same DB and in-memory tree.
///
/// # Safety
///
/// This function is marked unsafe because it performs memory-mapped file operations for the tree cache.
/// The caller must ensure that the cache file is not concurrently accessed or modified
/// by other processes while the tree is using it.
#[instrument(level = "info", skip_all)]
async unsafe fn run_both(
    db: DB,
    http_rpc_url: &str,
    ws_rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    http_cfg: HttpConfig,
) -> eyre::Result<()> {
    let tree_cache_cfg = &http_cfg.tree_cache;
    let batch_size = indexer_cfg.batch_size;

    // --- Phase 1: Backfill historical events into DB (no tree) ---
    let from = match db.world_tree_roots().get_latest_block().await? {
        Some(block) => block,
        None => indexer_cfg.start_block,
    };

    tracing::info!(
        from_block = from,
        batch_size,
        "Phase 1: starting historical backfill"
    );

    {
        let blockchain = Blockchain::new(http_rpc_url, ws_rpc_url, registry_address).await?;
        let (backfill_stream, last_block) = blockchain.backfill_events(from, batch_size);
        let committed_batches = save_events(&db, backfill_stream).await?;
        let backfill_up_to_block = last_block.load(Ordering::Relaxed);

        tracing::info!(
            committed_batches,
            backfill_up_to_block,
            "Phase 1: backfill complete, all historical events stored in DB"
        );
    } // blockchain dropped — provider no longer needed

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
    let rpc_url_clone = http_rpc_url.to_string();
    // Spawned tasks run for the lifetime of the process; they are not
    // joined because the Phase 4 retry loop below never returns.
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
        let rpc_url = http_rpc_url.to_string();
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

    process_registry_events(
        http_rpc_url,
        ws_rpc_url,
        registry_address,
        indexer_cfg,
        &db,
        Some(&tree_state),
    )
    .await?;

    http_handle.abort();
    if let Some(sanity_handle) = sanity_handle {
        sanity_handle.abort();
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

/// Process decoded backfill events from a stream, writing to DB only (no tree sync).
/// Returns the number of committed batches.
async fn save_events(
    db: &DB,
    mut stream: impl Stream<Item = BlockchainResult<BlockchainEvent<RegistryEvent>>> + Unpin,
) -> IndexerResult<usize> {
    let mut events_committer = EventsCommitter::new(db);
    let mut committed_batches = 0usize;

    while let Some(event_result) = stream.next().await {
        let event = event_result?;
        tracing::info!(?event, "processing backfill event");
        let committed = events_committer.handle_event(event).await?;
        if committed {
            committed_batches += 1;
        }
    }

    Ok(committed_batches)
}

/// Stream registry events from the blockchain and process them.
/// Restart when websocket connection is dropped.
#[instrument(level = "info", skip_all, fields(start_from))]
pub async fn process_registry_events(
    http_rpc_url: &str,
    ws_rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    db: &DB,
    tree_state: Option<&tree::TreeState>,
) -> IndexerResult<()> {
    // We re-create the blockchain connection (including backfill and websocket) when the stream
    // returns an error or the websocket connection is dropped.
    //
    // TOOD: Add smarter error handling. This could likely happen one level higher when there is
    // mismatch between root of the tree and on-chain tree.
    loop {
        tracing::info!("starting blockchain connection");

        let blockchain = match Blockchain::new(http_rpc_url, ws_rpc_url, registry_address).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(?e, "failed to create blockchain connection, retrying");
                tokio::time::sleep(BLOCKCHAIN_RETRY_DELAY).await;
                continue;
            }
        };

        let from = match db.world_tree_roots().get_latest_block().await? {
            Some(block) => block + 1,
            None => indexer_cfg.start_block,
        };

        let mut stream = blockchain.backfill_and_stream_events(from, indexer_cfg.batch_size);

        let mut events_committer = EventsCommitter::new(db);

        while let Some(event) = stream.next().await {
            match event {
                Ok(event) => {
                    if let Err(e) =
                        handle_registry_event(db, &mut events_committer, &event, tree_state).await
                    {
                        tracing::error!(?e, "error processing registry event");
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!(?e, "blockchain event stream error");
                    break;
                }
            }
        }

        tracing::warn!("restarting blockchain connection");
    }
}
