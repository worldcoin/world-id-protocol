use std::{net::SocketAddr, sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
};
use futures_util::StreamExt;
use sqlx::PgPool;
use world_id_core::world_id_registry::WorldIdRegistry;

mod blockchain;
pub mod config;
mod db;
mod routes;
mod sanity_check;
mod tree;

pub use crate::db::{
    EventType, fetch_recent_account_updates, get_latest_block, init_db, insert_account,
    insert_authenticator_at_index, make_db_pool, record_commitment_update,
    remove_authenticator_at_index, update_authenticator_at_index,
};
use crate::{
    blockchain::{Blockchain, BlockchainEvent, RegistryEvent},
    config::{AppState, HttpConfig, IndexerConfig, RunMode},
    db::get_max_event_id,
    tree::{GLOBAL_TREE, update_tree_with_commitment},
};
pub use config::GlobalConfig;

/// Tree cache parameters needed during indexing
#[derive(Clone)]
pub struct TreeCacheParams {
    pub cache_file_path: String,
    pub tree_depth: usize,
    pub dense_prefix_depth: usize,
}

async fn initialize_tree_with_config(
    tree_cache_cfg: &config::TreeCacheConfig,
    pool: &PgPool,
) -> anyhow::Result<()> {
    // Set the configured tree depth globally
    tree::set_tree_depth(tree_cache_cfg.tree_depth).await;

    let initializer = tree::TreeInitializer::new(
        tree_cache_cfg.cache_file_path.clone(),
        tree_cache_cfg.tree_depth,
        tree_cache_cfg.dense_tree_prefix_depth,
        U256::ZERO,
    );

    let new_tree = initializer.initialize(pool).await?;

    let root = new_tree.root();
    {
        let mut tree = GLOBAL_TREE.write().await;
        *tree = new_tree;
    }

    tracing::info!(
        root = %format!("0x{:x}", root),
        depth = tree_cache_cfg.tree_depth,
        "Tree initialized successfully"
    );
    Ok(())
}

/// Background task for HttpOnly mode: periodically check for stale cache and refresh
async fn cache_refresh_loop(
    tree_cache_cfg: config::TreeCacheConfig,
    pool: PgPool,
    refresh_interval_secs: u64,
) -> anyhow::Result<()> {
    let check_interval = Duration::from_secs(refresh_interval_secs);
    let cache_path = std::path::PathBuf::from(&tree_cache_cfg.cache_file_path);

    loop {
        tokio::time::sleep(check_interval).await;

        // Check if cache needs refresh
        match check_and_refresh_cache(&tree_cache_cfg, &pool, &cache_path).await {
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
    pool: &PgPool,
    cache_path: &std::path::Path,
) -> anyhow::Result<bool> {
    // Read current cache metadata
    let metadata = tree::metadata::read_metadata(cache_path)?;

    // Get current DB state
    let db_state = tree::metadata::get_db_state(pool).await?;

    let blocks_behind = db_state
        .max_block_number
        .saturating_sub(metadata.last_block_number);

    if blocks_behind == 0 {
        tracing::debug!("Cache is up-to-date");
        return Ok(false);
    }

    tracing::info!(
        cache_block = metadata.last_block_number,
        current_block = db_state.max_block_number,
        blocks_behind,
        "Cache is stale, refreshing"
    );

    // Re-initialize tree (will restore from cache + replay missed events)
    initialize_tree_with_config(tree_cache_cfg, pool).await?;

    Ok(true)
}

async fn update_tree_with_event(ev: &RegistryEvent) -> anyhow::Result<()> {
    match ev {
        RegistryEvent::AccountCreated(e) => {
            update_tree_with_commitment(e.leaf_index, e.offchain_signer_commitment).await
        }
        RegistryEvent::AccountUpdated(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await
        }
        RegistryEvent::AuthenticatorInserted(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await
        }
        RegistryEvent::AuthenticatorRemoved(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await
        }
        RegistryEvent::AccountRecovered(e) => {
            update_tree_with_commitment(e.leaf_index, e.new_offchain_signer_commitment).await
        }
    }
}

async fn start_http_server(
    rpc_url: &str,
    registry_address: Address,
    addr: SocketAddr,
    pool: PgPool,
) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().expect("invalid RPC URL"));
    let registry = WorldIdRegistry::new(registry_address, provider.erased());
    let router = routes::handler(AppState::new(pool, Arc::new(registry)));
    tracing::info!(%addr, "HTTP server listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, router).await?;
    Ok(())
}

pub async fn run_indexer(cfg: GlobalConfig) -> anyhow::Result<()> {
    tracing::info!("Connecting to DB...");
    let pool = make_db_pool(&cfg.db_url).await?;
    tracing::info!("Connection to DB successful. Initializing database...");
    init_db(&pool).await?;
    tracing::info!("🟢 Database successfully initialized.");

    let tree_cache_cfg = &cfg.tree_cache;

    match cfg.run_mode {
        RunMode::IndexerOnly { indexer_config } => {
            tracing::info!("Running in INDEXER-ONLY mode (no in-memory tree)");

            tracing::info!("Connecting to blockchain...");
            let blockchain =
                Blockchain::new(&cfg.http_rpc_url, &cfg.ws_rpc_url, cfg.registry_address).await?;
            tracing::info!("Connection to blockchain successful.");

            run_indexer_only(&blockchain, indexer_config, pool).await
        }
        RunMode::HttpOnly { http_config } => {
            tracing::info!("Running in HTTP-ONLY mode (initializing tree with cache)");
            // Initialize tree with cache for HTTP-only mode
            let start_time = std::time::Instant::now();
            initialize_tree_with_config(tree_cache_cfg, &pool).await?;
            tracing::info!("tree initialization took {:?}", start_time.elapsed());
            run_http_only(
                &cfg.http_rpc_url,
                cfg.registry_address,
                http_config,
                pool,
                tree_cache_cfg.clone(),
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
            initialize_tree_with_config(tree_cache_cfg, &pool).await?;
            tracing::info!("tree initialization took {:?}", start_time.elapsed());
            run_both(
                &blockchain,
                &cfg.http_rpc_url,
                cfg.registry_address,
                indexer_config,
                http_config,
                pool,
                TreeCacheParams {
                    cache_file_path: tree_cache_cfg.cache_file_path.clone(),
                    tree_depth: tree_cache_cfg.tree_depth,
                    dense_prefix_depth: tree_cache_cfg.dense_tree_prefix_depth,
                },
            )
            .await
        }
    }
}

async fn run_indexer_only(
    blockchain: &Blockchain,
    indexer_cfg: IndexerConfig,
    pool: PgPool,
) -> anyhow::Result<()> {
    // Determine starting block from checkpoint or env
    let mut from = get_latest_block(&pool)
        .await?
        .unwrap_or(indexer_cfg.start_block);

    // Backfill until head (update_tree = false for indexer-only mode)
    backfill(
        blockchain,
        &pool,
        &mut from,
        indexer_cfg.batch_size,
        None, // Don't update in-memory tree or cache in indexer-only mode
    )
    .await?;

    tracing::info!("switching to websocket live follow");
    stream_logs(
        blockchain, &pool, from,
        None, // Don't update in-memory tree or cache in indexer-only mode
    )
    .await?;

    Ok(())
}

async fn run_http_only(
    rpc_url: &str,
    registry_address: Address,
    http_cfg: HttpConfig,
    pool: PgPool,
    tree_cache_cfg: config::TreeCacheConfig,
) -> anyhow::Result<()> {
    // Start DB poller for account updates
    let poller_pool = pool.clone();
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
        sanity_handle = Some(tokio::spawn(async move {
            if let Err(e) =
                sanity_check::root_sanity_check_loop(rpc_url, registry_address, sanity_interval)
                    .await
            {
                tracing::error!(?e, "Root sanity checker failed");
            }
        }));
    }

    // Start cache refresh task in the background
    let refresh_pool = pool.clone();
    let refresh_interval = tree_cache_cfg.http_cache_refresh_interval_secs;
    let refresh_cache_cfg = tree_cache_cfg.clone();
    let cache_refresh_handle = tokio::spawn(async move {
        if let Err(e) = cache_refresh_loop(refresh_cache_cfg, refresh_pool, refresh_interval).await
        {
            tracing::error!(?e, "Cache refresh task failed");
        }
    });

    // Start HTTP server
    let http_result = start_http_server(rpc_url, registry_address, http_cfg.http_addr, pool).await;

    poller_handle.abort();
    cache_refresh_handle.abort();
    if let Some(handle) = sanity_handle {
        handle.abort();
    }
    http_result
}

async fn run_both(
    blockchain: &Blockchain,
    rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    http_cfg: HttpConfig,
    pool: PgPool,
    tree_cache_params: TreeCacheParams,
) -> anyhow::Result<()> {
    // Start HTTP server
    let http_pool = pool.clone();
    let http_addr = http_cfg.http_addr;
    let rpc_url_clone = rpc_url.to_string();
    let http_handle = tokio::spawn(async move {
        start_http_server(&rpc_url_clone, registry_address, http_addr, http_pool).await
    });

    // Start root sanity checker in the background
    let mut sanity_handle = None;
    if let Some(sanity_interval) = http_cfg.sanity_check_interval_secs {
        let rpc_url = rpc_url.to_string();
        sanity_handle = Some(tokio::spawn(async move {
            if let Err(e) =
                sanity_check::root_sanity_check_loop(rpc_url, registry_address, sanity_interval)
                    .await
            {
                tracing::error!(?e, "Root sanity checker failed");
            }
        }));
    }

    // Determine starting block from checkpoint or env
    let mut from = get_latest_block(&pool)
        .await?
        .unwrap_or(indexer_cfg.start_block);

    // Backfill until head (update_tree = true for both mode)
    backfill(
        blockchain,
        &pool,
        &mut from,
        indexer_cfg.batch_size,
        Some(&tree_cache_params), // Update in-memory tree and cache metadata after each batch
    )
    .await?;

    tracing::info!("switching to websocket live follow");
    stream_logs(
        blockchain,
        &pool,
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

async fn backfill_batch(
    blockchain: &Blockchain,
    pool: &PgPool,
    from_block: &mut u64,
    batch_size: u64,
    head: u64,
    tree_cache_params: Option<&TreeCacheParams>,
) -> anyhow::Result<()> {
    if *from_block == 0 {
        *from_block = 1;
    }

    let to_block = (*from_block + batch_size - 1).min(head);

    let events = blockchain
        .get_world_id_events(*from_block, to_block)
        .await?;

    if events.is_empty() {
        tracing::info!(
            count = events.len(),
            from = *from_block,
            to = to_block,
            "no events to process"
        );
        return Ok(());
    }

    tracing::info!(
        count = events.len(),
        from = *from_block,
        to = to_block,
        "processing registry logs"
    );

    for event in events {
        tracing::debug!(?event, "decoded registry event");

        if let Err(e) = handle_registry_event(pool, &event).await {
            tracing::error!(?e, ?event, "failed to handle registry event in DB");
        }

        if tree_cache_params.is_some()
            && let Err(e) = update_tree_with_event(&event.details).await
        {
            tracing::error!(?e, ?event, "failed to update tree for event");
        }
    }

    // Update cache metadata if tree was updated
    if let Some(cache_params) = tree_cache_params {
        let cache_path_buf = std::path::PathBuf::from(&cache_params.cache_file_path);
        let tree = GLOBAL_TREE.read().await;
        // Get the current max event ID to track replay position
        let current_event_id = get_max_event_id(pool).await.unwrap_or(0);
        tree::metadata::write_metadata(
            &cache_path_buf,
            &tree,
            pool,
            to_block,
            current_event_id,
            cache_params.tree_depth,
            cache_params.dense_prefix_depth,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(?e, "Failed to update cache metadata");
        });
    }

    tracing::debug!(
        from = *from_block,
        to = to_block,
        "✔️ finished processing batch until block {to_block}"
    );
    *from_block = to_block + 1;
    Ok(())
}

/// Backfill the entire history of the registry.
pub async fn backfill(
    blockchain: &Blockchain,
    pool: &PgPool,
    from_block: &mut u64,
    batch_size: u64,
    tree_cache_params: Option<&TreeCacheParams>,
) -> anyhow::Result<()> {
    let mut head = blockchain.get_block_number().await?;
    loop {
        match backfill_batch(
            blockchain,
            pool,
            from_block,
            batch_size,
            head,
            tree_cache_params,
        )
        .await
        {
            Ok(()) => {
                // Check if we're caught up to chain head
                let new_head = blockchain.get_block_number().await;
                if let Ok(new_head) = new_head {
                    head = new_head;
                } else {
                    tracing::error!("failed to get current chain head; retrying after delay");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                if *from_block > head {
                    tracing::info!(
                        from = *from_block,
                        head,
                        "✅ backfill complete, caught up to chain head"
                    );
                    break;
                }
            }
            Err(err) => {
                tracing::error!(?err, "backfill error; retrying after delay");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
    Ok(())
}

pub async fn handle_registry_event(
    pool: &PgPool,
    event: &BlockchainEvent<RegistryEvent>,
) -> anyhow::Result<()> {
    match &event.details {
        RegistryEvent::AccountCreated(ev) => {
            insert_account(
                pool,
                &ev.leaf_index,
                &ev.recovery_address,
                &ev.authenticator_addresses,
                &ev.authenticator_pubkeys,
                &ev.offchain_signer_commitment,
            )
            .await?;
            record_commitment_update(
                pool,
                ev.leaf_index,
                EventType::AccountCreated,
                ev.offchain_signer_commitment,
                event.block_number,
                &format!("{:?}", event.tx_hash),
                event.log_index,
            )
            .await?;
        }
        RegistryEvent::AccountUpdated(ev) => {
            update_authenticator_at_index(
                pool,
                ev.leaf_index,
                ev.pubkey_id,
                ev.new_authenticator_address,
                ev.new_authenticator_pubkey,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            record_commitment_update(
                pool,
                ev.leaf_index,
                EventType::AccountUpdated,
                ev.new_offchain_signer_commitment,
                event.block_number,
                &format!("{:?}", event.tx_hash),
                event.log_index,
            )
            .await?;
        }
        RegistryEvent::AuthenticatorInserted(ev) => {
            insert_authenticator_at_index(
                pool,
                ev.leaf_index,
                ev.pubkey_id,
                ev.authenticator_address,
                ev.new_authenticator_pubkey,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            record_commitment_update(
                pool,
                ev.leaf_index,
                EventType::AuthenticationInserted,
                ev.new_offchain_signer_commitment,
                event.block_number,
                &format!("{:?}", event.tx_hash),
                event.log_index,
            )
            .await?;
        }
        RegistryEvent::AuthenticatorRemoved(ev) => {
            remove_authenticator_at_index(
                pool,
                ev.leaf_index,
                ev.pubkey_id,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            record_commitment_update(
                pool,
                ev.leaf_index,
                EventType::AuthenticationRemoved,
                ev.new_offchain_signer_commitment,
                event.block_number,
                &format!("{:?}", event.tx_hash),
                event.log_index,
            )
            .await?;
        }
        RegistryEvent::AccountRecovered(ev) => {
            // Recovery resets to a single authenticator at index 0
            update_authenticator_at_index(
                pool,
                ev.leaf_index,
                0,
                ev.new_authenticator_address,
                ev.new_authenticator_pubkey,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            record_commitment_update(
                pool,
                ev.leaf_index,
                EventType::AccountRecovered,
                ev.new_offchain_signer_commitment,
                event.block_number,
                &format!("{:?}", event.tx_hash),
                event.log_index,
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn poll_db_changes(pool: PgPool, poll_interval_secs: u64) -> anyhow::Result<()> {
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

        match fetch_recent_account_updates(&pool, last_poll_time).await {
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
    pool: &PgPool,
    start_from: u64,
    tree_cache_params: Option<&TreeCacheParams>,
) -> anyhow::Result<()> {
    let mut stream = blockchain.stream_world_id_events(start_from).await?;
    while let Some(log) = stream.next().await {
        tracing::info!(?log, "processing live registry log");
        match log {
            Ok(event) => {
                tracing::info!(?event, "decoded live registry event");

                if let Err(e) = handle_registry_event(pool, &event).await {
                    tracing::error!(?e, ?event, "failed to handle registry event in DB");
                }

                if tree_cache_params.is_some()
                    && let Err(e) = update_tree_with_event(&event.details).await
                {
                    tracing::error!(?e, ?event, "failed to update tree for live event");
                }

                // Update cache metadata if tree was updated
                if let Some(cache_params) = tree_cache_params {
                    let cache_path_buf = std::path::PathBuf::from(&cache_params.cache_file_path);
                    let tree = GLOBAL_TREE.read().await;
                    // Get the current max event ID to track replay position
                    let current_event_id = get_max_event_id(pool).await.unwrap_or(0);
                    tree::metadata::write_metadata(
                        &cache_path_buf,
                        &tree,
                        pool,
                        event.block_number,
                        current_event_id,
                        cache_params.tree_depth,
                        cache_params.dense_prefix_depth,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        tracing::warn!(?e, "Failed to update cache metadata");
                    });
                }
            }
            Err(ref e) => {
                tracing::warn!(?e, ?log, "failed to decode live registry event");
            }
        }
    }
    Ok(())
}
