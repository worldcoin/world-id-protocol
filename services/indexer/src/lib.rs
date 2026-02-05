use crate::{
    blockchain::{Blockchain, BlockchainEvent, RegistryEvent},
    config::{AppState, HttpConfig, IndexerConfig, RunMode},
    db::{DB, fetch_recent_account_updates},
    events_committer::EventsCommitter,
    tree::{GLOBAL_TREE, update_tree_with_commitment},
};
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
};
use futures_util::StreamExt;
use std::{backtrace::Backtrace, net::SocketAddr, sync::Arc, time::Duration};
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

/// Tree cache parameters needed during indexing
#[derive(Clone)]
pub struct TreeCacheParams {
    pub cache_file_path: String,
    pub tree_depth: usize,
    pub dense_prefix_depth: usize,
}

async fn initialize_tree_with_config(
    tree_cache_cfg: &config::TreeCacheConfig,
    db: &DB,
) -> IndexerResult<tree::TreeState> {
    let initializer = tree::TreeInitializer::new(
        tree_cache_cfg.cache_file_path.clone(),
        tree_cache_cfg.tree_depth,
        tree_cache_cfg.dense_tree_prefix_depth,
        U256::ZERO,
    );

    let tree_state = initializer.initialize(db).await?;

    // Log the initialized root
    let root = tree_state.root().await;
    tracing::info!(
        root = %format!("0x{:x}", root),
        depth = tree_cache_cfg.tree_depth,
        "Tree initialized successfully"
    );
    Ok(tree_state)
}

/// Background task for HttpOnly mode: periodically check for stale cache and refresh
async fn cache_refresh_loop(
    tree_cache_cfg: config::TreeCacheConfig,
    db: &DB,
    refresh_interval_secs: u64,
    tree_state: tree::TreeState,
) -> IndexerResult<()> {
    let check_interval = Duration::from_secs(refresh_interval_secs);
    let cache_path = std::path::PathBuf::from(&tree_cache_cfg.cache_file_path);

    // Perform initial check immediately on startup (before first sleep)
    match check_and_refresh_cache(&tree_cache_cfg, db, &cache_path, &tree_state).await {
        Ok(refreshed) => {
            if refreshed {
                tracing::info!("Initial cache refresh completed with new events");
            }
        }
        Err(e) => {
            tracing::warn!(?e, "Initial cache refresh check failed, will retry");
        }
    }

    loop {
        tokio::time::sleep(check_interval).await;

        // Check if cache needs refresh
        match check_and_refresh_cache(&tree_cache_cfg, db, &cache_path, &tree_state).await {
            Ok(refreshed) => {
                if refreshed {
                    tracing::info!("Cache refreshed with new events");
                }
            }
            Err(e) => {
                tracing::warn!(?e, "Cache refresh check failed, will retry");
            }
        }
    }
}

/// Check if cache is stale and refresh if needed
async fn check_and_refresh_cache(
    tree_cache_cfg: &config::TreeCacheConfig,
    db: &DB,
    cache_path: &std::path::Path,
    tree_state: &tree::TreeState,
) -> IndexerResult<bool> {
    // Read current cache metadata
    let metadata = tree::metadata::read_metadata(cache_path)?;

    // Get current DB state
    let db_state = tree::metadata::get_db_state(db).await?;

    let last_event_id = db_state.last_event_id.unwrap_or_default();

    if metadata.last_block_number == last_event_id.block_number
        && metadata.last_log_index == last_event_id.log_index
    {
        tracing::debug!("Cache is up-to-date");
        return Ok(false);
    }

    let blocks_behind = last_event_id
        .block_number
        .saturating_sub(metadata.last_block_number);

    tracing::info!(
        cache_block = metadata.last_block_number,
        current_block = last_event_id.block_number,
        blocks_behind,
        "Cache is stale, refreshing"
    );

    let initializer = tree::TreeInitializer::new(
        tree_cache_cfg.cache_file_path.clone(),
        tree_cache_cfg.tree_depth,
        tree_cache_cfg.dense_tree_prefix_depth,
        U256::ZERO,
    );

    let (blocks_synced, logs_synced) = initializer.sync_with_db(db, tree_state).await?;
    tracing::info!(blocks_synced, logs_synced, "Cache refresh complete");

    Ok(blocks_synced > 0 || logs_synced > 0)
}

async fn update_tree_with_event(ev: &RegistryEvent) -> IndexerResult<()> {
    match ev {
        RegistryEvent::AccountCreated(e) => {
            update_tree_with_commitment(e.leaf_index, e.offchain_signer_commitment).await?;
        }
        RegistryEvent::AccountUpdated(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await?;
        }
        RegistryEvent::AuthenticatorInserted(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await?;
        }
        RegistryEvent::AuthenticatorRemoved(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await?;
        }
        RegistryEvent::AccountRecovered(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await?;
        }
        RegistryEvent::RootRecorded(_) => {}
    }
    Ok(())
}

async fn start_http_server(
    rpc_url: &str,
    registry_address: Address,
    addr: SocketAddr,
    db: DB,
    tree_state: tree::TreeState,
) -> IndexerResult<()> {
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

pub async fn run_indexer(cfg: GlobalConfig) -> IndexerResult<()> {
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
            // Initialize tree with cache for HTTP-only mode
            let start_time = std::time::Instant::now();
            let tree_cache_cfg = http_config.tree_cache.clone();
            let tree_state = initialize_tree_with_config(&tree_cache_cfg, &db).await?;
            tracing::info!("tree initialization took {:?}", start_time.elapsed());

            run_http_only(
                db,
                &cfg.http_rpc_url,
                cfg.registry_address,
                http_config,
                tree_cache_cfg,
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

            // Initialize tree with cache for both mode
            let start_time = std::time::Instant::now();
            let tree_cache_cfg = http_config.tree_cache.clone();
            let tree_state = initialize_tree_with_config(&tree_cache_cfg, &db).await?;
            tracing::info!("tree initialization took {:?}", start_time.elapsed());

            run_both(
                &blockchain,
                db,
                &cfg.http_rpc_url,
                cfg.registry_address,
                indexer_config,
                http_config,
                TreeCacheParams {
                    cache_file_path: tree_cache_cfg.cache_file_path.clone(),
                    tree_depth: tree_cache_cfg.tree_depth,
                    dense_prefix_depth: tree_cache_cfg.dense_tree_prefix_depth,
                },
                tree_state,
            )
            .await
        }
    }
}

async fn run_indexer_only(
    blockchain: &Blockchain,
    db: DB,
    indexer_cfg: IndexerConfig,
) -> IndexerResult<()> {
    // Determine starting block from checkpoint or env
    let from = db
        .world_tree_events()
        .get_latest_block()
        .await?
        .unwrap_or(indexer_cfg.start_block);

    tracing::info!("switching to websocket live follow");
    stream_logs(
        blockchain, &db, from,
        None, // Don't update in-memory tree or cache in indexer-only mode
    )
    .await?;

    Ok(())
}

async fn run_http_only(
    db: DB,
    rpc_url: &str,
    registry_address: Address,
    http_cfg: HttpConfig,
    tree_cache_cfg: config::TreeCacheConfig,
    tree_state: tree::TreeState,
) -> IndexerResult<()> {
    // Start DB poller for account updates
    let poller_pool = db.clone();
    let poll_interval = http_cfg.db_poll_interval_secs;
    let poller_handle = tokio::spawn(async move {
        if let Err(e) = poll_db_changes(poller_pool, poll_interval).await {
            tracing::error!(?e, "DB poller failed");
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

    // Start cache refresh task in the background
    let refresh_pool = db.clone();
    let refresh_interval = tree_cache_cfg.http_cache_refresh_interval_secs;
    let refresh_cache_cfg = tree_cache_cfg.clone();
    let refresh_tree_state = tree_state.clone();
    let cache_refresh_handle = tokio::spawn(async move {
        if let Err(e) =
            cache_refresh_loop(refresh_cache_cfg, &refresh_pool, refresh_interval, refresh_tree_state)
                .await
        {
            tracing::error!(?e, "Cache refresh task failed");
        }
    });

    // Start HTTP server
    let http_result =
        start_http_server(rpc_url, registry_address, http_cfg.http_addr, db, tree_state).await;

    poller_handle.abort();
    cache_refresh_handle.abort();
    if let Some(handle) = sanity_handle {
        handle.abort();
    }
    http_result
}

async fn run_both(
    blockchain: &Blockchain,
    db: DB,
    rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    http_cfg: HttpConfig,
    tree_cache_params: TreeCacheParams,
    tree_state: tree::TreeState,
) -> IndexerResult<()> {
    // Clone tree_state for sanity checker before moving into HTTP server spawn
    let sanity_tree_state = tree_state.clone();

    // Start HTTP server
    let http_pool = db.clone();
    let http_addr = http_cfg.http_addr;
    let rpc_url_clone = rpc_url.to_string();
    let http_handle = tokio::spawn(async move {
        start_http_server(&rpc_url_clone, registry_address, http_addr, http_pool, tree_state).await
    });

    // Start root sanity checker in the background
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

    // Determine starting block from checkpoint or env
    let from = db
        .world_tree_events()
        .get_latest_block()
        .await?
        .unwrap_or(indexer_cfg.start_block);

    tracing::info!("switching to websocket live follow");
    stream_logs(
        blockchain,
        &db,
        from,
        Some(&tree_cache_params), // Update in-memory tree and cache metadata after each event
    )
    .await?;

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
    tree_cache_params: Option<&TreeCacheParams>,
) -> IndexerResult<()> {
    events_committer.handle_event(event.clone()).await?;

    // Update cache metadata if tree was updated
    if let Some(cache_params) = tree_cache_params {
        if let Err(e) = update_tree_with_event(&event.details).await {
            tracing::error!(?e, ?event, "failed to update tree for live event");
        }

        let cache_path_buf = std::path::PathBuf::from(&cache_params.cache_file_path);
        let tree = GLOBAL_TREE.read().await;

        // Get the current max event ID to track replay position
        let current_event_id = db
            .world_tree_events()
            .get_latest_id()
            .await?
            .unwrap_or_default();

        tree::metadata::write_metadata(
            &cache_path_buf,
            &tree,
            db,
            current_event_id,
            cache_params.tree_depth,
            cache_params.dense_prefix_depth,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(?e, "Failed to update cache metadata");
        });
    }

    Ok(())
}

pub async fn poll_db_changes(db: DB, poll_interval_secs: u64) -> IndexerResult<()> {
    tracing::info!(
        poll_interval_secs,
        "Starting DB polling for account updates..."
    );

    // Track the last known max update timestamp
    let mut last_poll_time = std::time::SystemTime::now();

    loop {
        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;

        // Query for accounts that have been updated since last poll
        let current_time = std::time::SystemTime::now();

        match fetch_recent_account_updates(db.pool(), last_poll_time).await {
            Ok(updates) => {
                if !updates.is_empty() {
                    tracing::info!(count = updates.len(), "Found account updates from DB");

                    for (leaf_index, commitment) in updates {
                        tracing::debug!(
                            leaf_index = %leaf_index,
                            commitment = %commitment,
                            "Updating tree from DB poll"
                        );

                        if let Err(e) = update_tree_with_commitment(leaf_index, commitment).await {
                            tracing::error!(
                                ?e,
                                leaf_index = %leaf_index,
                                "Failed to update tree from DB poll"
                            );
                        }
                    }
                }

                last_poll_time = current_time;
            }
            Err(e) => {
                tracing::error!(?e, "Failed to fetch account updates from DB");
            }
        }
    }
}

pub async fn stream_logs(
    blockchain: &Blockchain,
    db: &DB,
    start_from: u64,
    tree_cache_params: Option<&TreeCacheParams>,
) -> IndexerResult<()> {
    let mut stream = blockchain.stream_world_tree_events(start_from).await?;
    let mut events_committer = EventsCommitter::new(db);

    while let Some(log) = stream.next().await {
        tracing::info!(?log, "processing live registry log");
        match log {
            Ok(event) => {
                tracing::info!(?event, "decoded live registry event");

                if let Err(e) =
                    handle_registry_event(db, &mut events_committer, &event, tree_cache_params)
                        .await
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
