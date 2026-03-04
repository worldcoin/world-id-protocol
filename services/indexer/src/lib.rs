#![recursion_limit = "256"]

use crate::{
    blockchain::{Blockchain, BlockchainEvent, RegistryEvent},
    config::{AppState, HttpConfig, IndexerConfig, RunMode},
    db::DB,
    events_committer::EventsCommitter,
    rollback_executor::rollback_to_last_valid_root,
};
use alloy::{primitives::Address, providers::DynProvider};
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
pub mod events_processor;
pub mod metrics;
pub mod rollback_executor;
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

        let count = tree::cached_tree::sync_from_db(&db, &tree_state).await?;

        if count > 0 {
            tracing::info!(count, "Synced events from DB to tree");
        }
    }
}

#[instrument(level = "info", skip_all, fields(%addr))]
async fn start_http_server(
    http_provider: DynProvider,
    registry_address: Address,
    addr: SocketAddr,
    db: DB,
    tree_state: tree::TreeState,
    request_timeout_secs: u64,
) -> eyre::Result<()> {
    let registry = WorldIdRegistry::new(registry_address, http_provider);
    let router = routes::handler(
        AppState::new(db, Arc::new(registry), tree_state),
        request_timeout_secs,
    );
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

    let http_provider = cfg.provider.http().await?;

    match cfg.run_mode {
        RunMode::IndexerOnly { indexer_config } => {
            tracing::info!("Running in INDEXER-ONLY mode");
            let start_time = std::time::Instant::now();
            let tree_state = unsafe { initialize_tree_with_config(&cfg.tree_cache, &db).await? };
            tracing::info!("tree initialization took {:?}", start_time.elapsed());

            run_indexer_only(
                db,
                http_provider,
                &cfg.ws_rpc_url,
                cfg.registry_address,
                indexer_config,
                tree_state,
            )
            .await
        }
        RunMode::HttpOnly { http_config } => {
            tracing::info!("Running in HTTP-ONLY mode (initializing tree with cache)");
            let start_time = std::time::Instant::now();
            let tree_state = unsafe { initialize_tree_with_config(&cfg.tree_cache, &db).await? };
            tracing::info!("tree initialization took {:?}", start_time.elapsed());

            run_http_only(
                db,
                http_provider,
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
            let start_time = std::time::Instant::now();
            let tree_state = unsafe { initialize_tree_with_config(&cfg.tree_cache, &db).await? };
            tracing::info!("tree initialization took {:?}", start_time.elapsed());

            run_both(
                db,
                http_provider,
                &cfg.ws_rpc_url,
                cfg.registry_address,
                indexer_config,
                http_config,
                tree_state,
            )
            .await
        }
    }
}

#[instrument(level = "info", skip_all)]
async fn run_indexer_only(
    db: DB,
    http_provider: DynProvider,
    ws_rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    tree_state: tree::TreeState,
) -> eyre::Result<()> {
    process_registry_events(
        http_provider,
        ws_rpc_url,
        registry_address,
        indexer_cfg,
        &db,
        &tree_state,
    )
    .await?;

    Ok(())
}

#[instrument(level = "info", skip_all)]
async fn run_http_only(
    db: DB,
    http_provider: DynProvider,
    registry_address: Address,
    http_cfg: HttpConfig,
    tree_state: tree::TreeState,
) -> eyre::Result<()> {
    // Start tree sync loop
    let sync_pool = db.clone();
    let sync_interval = http_cfg.db_poll_interval_secs;
    let sync_tree_state = tree_state.clone();
    let sync_handle =
        tokio::spawn(
            async move { tree_sync_loop(sync_pool, sync_interval, sync_tree_state).await },
        );

    // Start root sanity checker in the background
    let sanity_handle = if let Some(sanity_interval) = http_cfg.sanity_check_interval_secs {
        let sanity_provider = http_provider.clone();
        let sanity_tree_state = tree_state.clone();
        Some(tokio::spawn(async move {
            sanity_check::root_sanity_check_loop(
                sanity_provider,
                registry_address,
                sanity_interval,
                sanity_tree_state,
            )
            .await
        }))
    } else {
        None
    };

    // Start HTTP server
    let http_addr = http_cfg.http_addr;
    let request_timeout_secs = http_cfg.request_timeout_secs;
    let http_handle = tokio::spawn(async move {
        start_http_server(
            http_provider,
            registry_address,
            http_addr,
            db,
            tree_state,
            request_timeout_secs,
        )
        .await
    });

    // Wait for the first task to complete — any failure is fatal.
    tokio::select! {
        result = sync_handle => {
            result??;
            eyre::bail!("tree sync loop exited unexpectedly");
        }
        result = http_handle => {
            result??;
            Ok(())
        }
        result = async { sanity_handle.unwrap().await }, if sanity_handle.is_some() => {
            result??;
            eyre::bail!("sanity check loop exited unexpectedly");
        }
    }
}

/// Runs both the indexer and HTTP server in the same process, sharing the same DB and in-memory tree.
#[instrument(level = "info", skip_all)]
async fn run_both(
    db: DB,
    http_provider: DynProvider,
    ws_rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    http_cfg: HttpConfig,
    tree_state: tree::TreeState,
) -> eyre::Result<()> {
    // --- Start HTTP server + sanity check ---
    let http_tree_state = tree_state.clone();
    let sanity_tree_state = tree_state.clone();

    let http_pool = db.clone();
    let http_addr = http_cfg.http_addr;
    let request_timeout_secs = http_cfg.request_timeout_secs;
    let http_provider_clone = http_provider.clone();
    // Spawned tasks run for the lifetime of the process; they are not
    // joined because the event streaming loop below never returns.
    let http_handle = tokio::spawn(async move {
        start_http_server(
            http_provider_clone,
            registry_address,
            http_addr,
            http_pool,
            http_tree_state,
            request_timeout_secs,
        )
        .await
    });

    let sanity_handle = if let Some(sanity_interval) = http_cfg.sanity_check_interval_secs {
        let sanity_provider = http_provider.clone();
        Some(tokio::spawn(async move {
            sanity_check::root_sanity_check_loop(
                sanity_provider,
                registry_address,
                sanity_interval,
                sanity_tree_state,
            )
            .await
        }))
    } else {
        None
    };

    // Stream live events; wait for the first task to complete — any failure is fatal.
    tokio::select! {
        result = process_registry_events(
            http_provider,
            ws_rpc_url,
            registry_address,
            indexer_cfg,
            &db,
            &tree_state,
        ) => {
            result?;
            Ok(())
        }
        result = http_handle => {
            result??;
            eyre::bail!("HTTP server exited unexpectedly");
        }
        result = async { sanity_handle.unwrap().await }, if sanity_handle.is_some() => {
            result??;
            eyre::bail!("sanity check loop exited unexpectedly");
        }
    }
}

pub async fn handle_registry_event<'a>(
    events_committer: &mut EventsCommitter<'a>,
    event: BlockchainEvent<RegistryEvent>,
) -> IndexerResult<()> {
    events_committer.handle_event(event).await?;
    Ok(())
}

/// Stream registry events from the blockchain and process them.
/// Restart when websocket connection is dropped.
#[instrument(level = "info", skip_all, fields(start_from))]
pub async fn process_registry_events(
    http_provider: DynProvider,
    ws_rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    db: &DB,
    tree_state: &tree::TreeState,
) -> IndexerResult<()> {
    // We re-create the blockchain connection (including backfill and websocket) when the stream
    // returns an error or the websocket connection is dropped.
    loop {
        tracing::info!("starting blockchain connection");

        let blockchain =
            match Blockchain::new(http_provider.clone(), ws_rpc_url, registry_address).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(?e, "failed to create blockchain connection, retrying");
                    tokio::time::sleep(BLOCKCHAIN_RETRY_DELAY).await;
                    continue;
                }
            };

        let from = match db.world_id_registry_events().get_latest_block().await? {
            Some(block) => block + 1,
            None => indexer_cfg.start_block,
        };

        let mut stream = blockchain.backfill_and_stream_events(from, indexer_cfg.batch_size);

        let versioned_tree =
            tree::VersionedTreeState::new(tree_state.clone(), indexer_cfg.tree_max_block_age);
        let mut events_committer = EventsCommitter::new(db, versioned_tree.clone());

        while let Some(event) = stream.next().await {
            match event {
                Ok(event) => {
                    let block_number = event.block_number;
                    match handle_registry_event(&mut events_committer, event).await {
                        Ok(()) => {
                            crate::metrics::set_chain_processed_block(block_number);
                        }
                        Err(IndexerError::ReorgDetected {
                            block_number,
                            reason,
                        }) => {
                            tracing::warn!(
                                block_number,
                                reason,
                                "Reorg detected during event commit, rolling back"
                            );
                            match rollback_to_last_valid_root(
                                db,
                                &http_provider,
                                registry_address,
                                &versioned_tree,
                            )
                            .await
                            {
                                Ok(Some(target)) => {
                                    tracing::info!(?target, "rolled back successfully");
                                    return Err(IndexerError::ReorgDetected {
                                        block_number: target.block_number,
                                        reason: "rolled back to last valid root, restart required"
                                            .to_string(),
                                    });
                                }
                                Ok(None) => {
                                    return Err(IndexerError::ReorgDetected {
                                        block_number,
                                        reason: "no valid root found during rollback".to_string(),
                                    });
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        Err(e) => return Err(e),
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
