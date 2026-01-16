use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use sqlx::PgPool;
use world_id_core::world_id_registry::WorldIdRegistry;

pub mod config;
mod db;
mod events;
mod routes;
mod sanity_check;
mod tree;

use crate::config::{AppState, HttpConfig, IndexerConfig, RunMode};
pub use crate::db::{
    fetch_recent_account_updates, init_db, insert_account, insert_authenticator_at_index,
    load_checkpoint, make_db_pool, record_commitment_update, remove_authenticator_at_index,
    save_checkpoint, update_authenticator_at_index,
};
use crate::events::decoders::decode_registry_event;
use crate::events::RegistryEvent;
use crate::tree::{build_tree_from_db, update_tree_with_commitment};
pub use config::GlobalConfig;

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
    let pool = make_db_pool(&cfg.db_url).await?;
    tracing::info!("Connection to DB successful. Initializing database...");
    init_db(&pool).await?;
    tracing::info!("🟢 Database successfully initialized.");

    let rpc_url = &cfg.rpc_url;
    let registry_address = cfg.registry_address;

    match cfg.run_mode {
        RunMode::IndexerOnly { indexer_config } => {
            tracing::info!("Running in INDEXER-ONLY mode (no in-memory tree)");
            run_indexer_only(rpc_url, registry_address, indexer_config, pool).await
        }
        RunMode::HttpOnly { http_config } => {
            tracing::info!("Running in HTTP-ONLY mode (building tree from DB)");
            // Build tree from DB for HTTP-only mode
            let start_time = std::time::Instant::now();
            build_tree_from_db(&pool).await?;
            tracing::info!("building tree from DB took {:?}", start_time.elapsed());
            run_http_only(rpc_url, registry_address, http_config, pool).await
        }
        RunMode::Both {
            indexer_config,
            http_config,
        } => {
            tracing::info!("Running in BOTH mode (indexer + HTTP server)");
            // Build tree from DB for both mode
            let start_time = std::time::Instant::now();
            build_tree_from_db(&pool).await?;
            tracing::info!("building tree from DB took {:?}", start_time.elapsed());
            run_both(rpc_url, registry_address, indexer_config, http_config, pool).await
        }
    }
}

async fn run_indexer_only(
    rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    pool: PgPool,
) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().expect("invalid RPC URL"));

    // Determine starting block from checkpoint or env
    let mut from = load_checkpoint(&pool)
        .await?
        .unwrap_or(indexer_cfg.start_block);

    // Backfill until head (update_tree = false for indexer-only mode)
    backfill(
        &provider,
        &pool,
        registry_address,
        &mut from,
        indexer_cfg.batch_size,
        false, // Don't update in-memory tree
    )
    .await?;

    tracing::info!("switching to websocket live follow");
    stream_logs(&indexer_cfg.ws_url, &pool, registry_address, from, false).await?;

    Ok(())
}

async fn run_http_only(
    rpc_url: &str,
    registry_address: Address,
    http_cfg: HttpConfig,
    pool: PgPool,
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

    // Start HTTP server
    let http_result = start_http_server(rpc_url, registry_address, http_cfg.http_addr, pool).await;

    poller_handle.abort();
    if let Some(handle) = sanity_handle {
        handle.abort();
    }
    http_result
}

async fn run_both(
    rpc_url: &str,
    registry_address: Address,
    indexer_cfg: IndexerConfig,
    http_cfg: HttpConfig,
    pool: PgPool,
) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().expect("invalid RPC URL"));

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
    let mut from = load_checkpoint(&pool)
        .await?
        .unwrap_or(indexer_cfg.start_block);

    // Backfill until head (update_tree = true for both mode)
    backfill(
        &provider,
        &pool,
        registry_address,
        &mut from,
        indexer_cfg.batch_size,
        true, // Update in-memory tree directly from events
    )
    .await?;

    tracing::info!("switching to websocket live follow");
    stream_logs(&indexer_cfg.ws_url, &pool, registry_address, from, true).await?;

    http_handle.abort();
    if let Some(handle) = sanity_handle {
        handle.abort();
    }
    Ok(())
}

async fn backfill_batch<P: Provider>(
    provider: &P,
    pool: &PgPool,
    registry: Address,
    from_block: &mut u64,
    batch_size: u64,
    update_tree: bool,
    head: u64,
) -> anyhow::Result<()> {
    if *from_block == 0 {
        *from_block = 1;
    }

    let to_block = (*from_block + batch_size - 1).min(head);

    // Listen for all events that change commitment
    let event_signatures = vec![
        WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
        WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
        WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
        WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
        WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
    ];

    let filter = Filter::new()
        .address(registry)
        .event_signature(event_signatures)
        .from_block(*from_block)
        .to_block(to_block);

    let logs = provider.get_logs(&filter).await?;
    if !logs.is_empty() {
        tracing::info!(
            count = logs.len(),
            from = *from_block,
            to = to_block,
            "processing registry logs"
        );
    }
    for lg in logs {
        match decode_registry_event(&lg) {
            Ok(event) => {
                tracing::debug!(?event, "decoded registry event");
                let block_number = lg.block_number;
                let tx_hash = lg.transaction_hash;
                let log_index = lg.log_index;

                if let Err(e) =
                    handle_registry_event(pool, &event, block_number, tx_hash, log_index).await
                {
                    tracing::error!(?e, ?event, "failed to handle registry event in DB");
                }

                if update_tree {
                    if let Err(e) = update_tree_with_event(&event).await {
                        tracing::error!(?e, ?event, "failed to update tree for event");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(?e, ?lg, "failed to decode registry event");
            }
        }
    }

    save_checkpoint(pool, to_block).await?;
    tracing::debug!(
        from = *from_block,
        to = to_block,
        "✔️ finished processing batch until block {to_block}"
    );
    *from_block = to_block + 1;
    Ok(())
}

/// Backfill the entire history of the registry.
pub async fn backfill<P: Provider>(
    provider: &P,
    pool: &PgPool,
    registry: Address,
    from_block: &mut u64,
    batch_size: u64,
    update_tree: bool,
) -> anyhow::Result<()> {
    let mut head = provider.get_block_number().await?;
    loop {
        match backfill_batch(
            provider,
            pool,
            registry,
            from_block,
            batch_size,
            update_tree,
            head,
        )
        .await
        {
            Ok(()) => {
                // Check if we're caught up to chain head
                let new_head = provider.get_block_number().await;
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
    event: &RegistryEvent,
    block_number: Option<u64>,
    tx_hash: Option<alloy::primitives::B256>,
    log_index: Option<u64>,
) -> anyhow::Result<()> {
    match event {
        RegistryEvent::AccountCreated(ev) => {
            insert_account(pool, ev).await?;
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "created",
                    ev.offchain_signer_commitment,
                    bn,
                    &format!("{tx:?}"),
                    li,
                )
                .await?;
            }
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
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "updated",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{tx:?}"),
                    li,
                )
                .await?;
            }
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
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "inserted",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{tx:?}"),
                    li,
                )
                .await?;
            }
        }
        RegistryEvent::AuthenticatorRemoved(ev) => {
            remove_authenticator_at_index(
                pool,
                ev.leaf_index,
                ev.pubkey_id,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "removed",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{tx:?}"),
                    li,
                )
                .await?;
            }
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
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "recovered",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{tx:?}"),
                    li,
                )
                .await?;
            }
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

pub async fn update_tree_with_event(ev: &RegistryEvent) -> anyhow::Result<()> {
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

pub async fn stream_logs(
    ws_url: &str,
    pool: &PgPool,
    registry: Address,
    start_from: u64,
    update_tree: bool,
) -> anyhow::Result<()> {
    use futures_util::StreamExt;
    let ws = WsConnect::new(ws_url);
    let provider = ProviderBuilder::new().connect_ws(ws).await?;

    let event_signatures = vec![
        WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
        WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
        WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
        WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
        WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
    ];

    let filter = Filter::new()
        .address(registry)
        .event_signature(event_signatures)
        .from_block(start_from);
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();
    while let Some(log) = stream.next().await {
        tracing::info!(?log, "processing live registry log");
        match decode_registry_event(&log) {
            Ok(event) => {
                tracing::info!(?event, "decoded live registry event");
                let block_number = log.block_number;
                let tx_hash = log.transaction_hash;
                let log_index = log.log_index;

                if let Err(e) =
                    handle_registry_event(pool, &event, block_number, tx_hash, log_index).await
                {
                    tracing::error!(?e, ?event, "failed to handle registry event in DB");
                }

                if update_tree {
                    if let Err(e) = update_tree_with_event(&event).await {
                        tracing::error!(?e, ?event, "failed to update tree for live event");
                    }
                }

                if let Some(bn) = log.block_number {
                    save_checkpoint(pool, bn).await?;
                }
            }
            Err(e) => {
                tracing::warn!(?e, ?log, "failed to decode live registry event");
            }
        }
    }
    Ok(())
}
