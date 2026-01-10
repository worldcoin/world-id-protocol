use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use alloy::primitives::{Address, Log, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use ark_bn254::Fr;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T2_PARAMS};
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use semaphore_rs_trees::proof::InclusionProof;
use semaphore_rs_trees::Branch;
use sqlx::migrate::Migrator;
use sqlx::{postgres::PgPoolOptions, types::Json, PgPool, Row};
use tokio::sync::RwLock;
use world_id_core::world_id_registry::WorldIdRegistry;
use world_id_primitives::TREE_DEPTH;

pub mod config;
mod error;
mod routes;
mod sanity_check;
use crate::config::{AppState, HttpConfig, IndexerConfig, RunMode};
pub use config::GlobalConfig;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

// Event signatures for all registry events that change commitment
fn event_signatures() -> Vec<alloy::primitives::FixedBytes<32>> {
    vec![
        WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
        WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
        WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
        WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
        WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
    ]
}

#[derive(Debug, Clone)]
pub struct AccountCreatedEvent {
    pub leaf_index: U256,
    pub recovery_address: Address,
    pub authenticator_addresses: Vec<Address>,
    pub authenticator_pubkeys: Vec<U256>,
    pub offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AccountUpdatedEvent {
    pub leaf_index: U256,
    pub pubkey_id: u32,
    pub new_authenticator_pubkey: U256,
    pub old_authenticator_address: Address,
    pub new_authenticator_address: Address,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorInsertedEvent {
    pub leaf_index: U256,
    pub pubkey_id: u32,
    pub authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorRemovedEvent {
    pub leaf_index: U256,
    pub pubkey_id: u32,
    pub authenticator_address: Address,
    pub authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AccountRecoveredEvent {
    pub leaf_index: U256,
    pub new_authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub enum RegistryEvent {
    AccountCreated(AccountCreatedEvent),
    AccountUpdated(AccountUpdatedEvent),
    AuthenticatorInserted(AuthenticatorInsertedEvent),
    AuthenticatorRemoved(AuthenticatorRemovedEvent),
    AccountRecovered(AccountRecoveredEvent),
}

static POSEIDON_HASHER: LazyLock<Poseidon2<Fr, 2, 5>> =
    LazyLock::new(|| Poseidon2::new(&POSEIDON2_BN254_T2_PARAMS));

struct PoseidonHasher {}

impl Hasher for PoseidonHasher {
    type Hash = U256;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let left: Fr = left.try_into().unwrap();
        let right: Fr = right.try_into().unwrap();
        let mut input = [left, right];
        let feed_forward = input[0];
        POSEIDON_HASHER.permutation_in_place(&mut input);
        input[0] += feed_forward;
        input[0].into()
    }
}

fn tree_capacity() -> usize {
    1usize << TREE_DEPTH
}

// Global Merkle tree (singleton). Protected by an async RwLock for concurrent reads.
pub(crate) static GLOBAL_TREE: LazyLock<RwLock<MerkleTree<PoseidonHasher, Canonical>>> =
    LazyLock::new(|| RwLock::new(MerkleTree::<PoseidonHasher>::new(TREE_DEPTH, U256::ZERO)));

async fn set_leaf_at_index(leaf_index: usize, value: U256) -> anyhow::Result<()> {
    if leaf_index >= tree_capacity() {
        anyhow::bail!("leaf index {leaf_index} out of range for tree depth {TREE_DEPTH}");
    }

    let mut tree = GLOBAL_TREE.write().await;
    take_mut::take(&mut *tree, |tree| {
        tree.update_with_mutation(leaf_index, &value)
    });
    Ok(())
}

async fn build_tree_from_db(pool: &PgPool) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "select leaf_index, offchain_signer_commitment from accounts order by leaf_index asc",
    )
    .fetch_all(pool)
    .await?;

    tracing::info!("There are {:?} rows in the table.", rows.len());

    let mut leaves: Vec<(usize, U256)> = Vec::with_capacity(rows.len());
    for r in rows {
        let leaf_index: String = r.get("leaf_index");
        let offchain: String = r.get("offchain_signer_commitment");
        let leaf_index: U256 = leaf_index.parse::<U256>()?;
        if leaf_index == U256::ZERO {
            continue;
        }
        let leaf_index = leaf_index.as_limbs()[0] as usize;
        let leaf_val = offchain.parse::<U256>()?;
        leaves.push((leaf_index, leaf_val));
    }

    let mut new_tree = MerkleTree::<PoseidonHasher>::new(TREE_DEPTH, U256::ZERO);
    for (idx, value) in leaves {
        if idx >= tree_capacity() {
            anyhow::bail!(
                "leaf index {idx} out of range while rebuilding tree (depth {TREE_DEPTH})",
            );
        }
        new_tree = new_tree.update_with_mutation(idx, &value);
    }

    let root = new_tree.root();
    {
        let mut tree = GLOBAL_TREE.write().await;
        *tree = new_tree;
    }
    tracing::info!(
        root = %format!("0x{:x}", root),
        depth = TREE_DEPTH,
        "tree built from DB"
    );
    Ok(())
}

async fn update_tree_with_commitment(leaf_index: U256, new_commitment: U256) -> anyhow::Result<()> {
    if leaf_index == 0 {
        anyhow::bail!("account index cannot be zero");
    }
    let leaf_index = leaf_index.as_limbs()[0] as usize;
    set_leaf_at_index(leaf_index, new_commitment).await?;
    Ok(())
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

fn proof_to_vec(proof: &InclusionProof<PoseidonHasher>) -> Vec<U256> {
    proof
        .0
        .iter()
        .map(|b| match b {
            Branch::Left(sib) => *sib,
            Branch::Right(sib) => *sib,
        })
        .collect()
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
    let pool = make_db_pool(&cfg.db_url).await?;
    init_db(&pool).await?;

    tracing::info!("Connection to DB successful, running migrations.");
    MIGRATOR.run(&pool).await.expect("failed to run migrations");
    tracing::info!("🟢 Migrations synced successfully.");

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
    index_task(
        rpc_url,
        &pool,
        registry_address,
        indexer_cfg.start_block,
        indexer_cfg.batch_size,
        false, // Don't update in-memory tree
    )
    .await?;

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

    // Spawn indexer task
    let indexer_pool = pool.clone();
    let indexer_rpc_url = rpc_url.to_string();
    let indexer_registry = registry_address;
    let indexer_start_block = indexer_cfg.start_block;
    let indexer_batch_size = indexer_cfg.batch_size;
    let indexer_handle = tokio::spawn(async move {
        index_task(
            &indexer_rpc_url,
            &indexer_pool,
            indexer_registry,
            indexer_start_block,
            indexer_batch_size,
            true, // Update in-memory tree directly from events
        )
        .await
    });

    // Get abort handles before select (select moves the handles)
    let http_abort = http_handle.abort_handle();
    let indexer_abort = indexer_handle.abort_handle();
    let sanity_abort = sanity_handle.as_ref().map(|h| h.abort_handle());

    // Wait for any task to complete
    tokio::select! {
        http_result = http_handle => {
            // HTTP server completed (or errored)
            if let Err(e) = http_result {
                tracing::error!(?e, "HTTP server task panicked");
            } else if let Err(e) = http_result.unwrap() {
                tracing::error!(?e, "HTTP server exited with error");
            } else {
                tracing::info!("HTTP server exited normally");
            }

            // Gracefully shut down other tasks
            indexer_abort.abort();
            if let Some(abort) = sanity_abort {
                abort.abort();
            }
        }
        indexer_result = indexer_handle => {
            // Indexer task completed (or errored)
            if let Err(e) = indexer_result {
                tracing::error!(?e, "Indexer task panicked");
            } else if let Err(e) = indexer_result.unwrap() {
                tracing::error!(?e, "Indexer exited with error");
            } else {
                tracing::info!("Indexer exited normally");
            }

            // Gracefully shut down other tasks
            http_abort.abort();
            if let Some(abort) = sanity_abort {
                abort.abort();
            }
        }
        sanity_result = async {
            match sanity_handle {
                Some(handle) => handle.await,
                None => std::future::pending().await,
            }
        } => {
            // Sanity checker completed (shouldn't normally happen, but handle it)
            if let Err(e) = sanity_result {
                tracing::error!(?e, "Sanity checker task panicked");
            } else {
                tracing::warn!("Sanity checker task completed unexpectedly");
            }

            // Gracefully shut down other tasks
            http_abort.abort();
            indexer_abort.abort();
        }
    }

    Ok(())
}

pub async fn make_db_pool(db_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(db_url)
        .await?;
    Ok(pool)
}

pub async fn init_db(pool: &PgPool) -> anyhow::Result<()> {
    // Run sqlx migrations from ./migrations
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub async fn load_checkpoint(pool: &PgPool) -> anyhow::Result<Option<u64>> {
    let rec: Option<(i64,)> = sqlx::query_as("select last_block from checkpoints where name = $1")
        .bind("account_created")
        .fetch_optional(pool)
        .await?;
    Ok(rec.map(|t| t.0 as u64))
}

pub async fn save_checkpoint(pool: &PgPool, block: u64) -> anyhow::Result<()> {
    let result = sqlx::query(
        "insert into checkpoints (name, last_block) values ($1, $2) 
         on conflict (name) do update set last_block = excluded.last_block 
         where excluded.last_block > checkpoints.last_block",
    )
    .bind("account_created")
    .bind(block as i64)
    .execute(pool)
    .await?;

    // If no rows were affected, it means the block number wasn't greater than the existing one
    if result.rows_affected() == 0 && tracing::enabled!(tracing::Level::DEBUG) {
        let existing_block = load_checkpoint(pool).await?.unwrap_or(0);
        tracing::debug!(
            attempted_block = block,
            existing_block,
            "checkpoint not updated: block number not greater than existing checkpoint"
        );
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

    // Process batches until caught up to head
    while *from_block <= head {
        let to_block = (*from_block + batch_size - 1).min(head);

        let filter = Filter::new()
            .address(registry)
            .event_signature(event_signatures())
            .from_block(*from_block)
            .to_block(to_block);

        let mut logs = provider.get_logs(&filter).await?;

        // Sort logs by block number, then by log index to ensure correct processing order
        // The RPC spec doesn't guarantee order, so we must sort explicitly
        logs.sort_by(|a, b| {
            match (a.block_number, b.block_number) {
                (Some(a_bn), Some(b_bn)) => {
                    let block_cmp = a_bn.cmp(&b_bn);
                    if block_cmp != std::cmp::Ordering::Equal {
                        return block_cmp;
                    }
                    // Within the same block, sort by log index
                    match (a.log_index, b.log_index) {
                        (Some(a_li), Some(b_li)) => a_li.cmp(&b_li),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });

        if !logs.is_empty() {
            tracing::info!(
                count = logs.len(),
                from = *from_block,
                to = to_block,
                "processing registry logs"
            );
        }
        for lg in logs {
            let event = decode_registry_event(&lg)?;
            tracing::debug!(?event, "decoded registry event");
            let block_number = lg.block_number;
            let tx_hash = lg.transaction_hash;
            let log_index = lg.log_index;

            // Deduplication: Check if this event has already been processed
            if let (Some(tx), Some(li)) = (tx_hash, log_index) {
                if is_event_already_processed(pool, &tx, li).await? {
                    tracing::debug!(
                        tx_hash = ?tx,
                        log_index = li,
                        block_number = ?block_number,
                        "event already processed, skipping"
                    );
                    continue;
                }
            }

            if let Some(bn) = block_number {
                handle_registry_event(pool, &event, bn, tx_hash, log_index).await?;
                if update_tree {
                    update_tree_with_event(&event).await?;
                }
            }
        }
        save_checkpoint(pool, to_block).await?;
        tracing::info!(
            from = *from_block,
            to = to_block,
            "✔️ finished processing batch until block {to_block}"
        );
        *from_block = to_block + 1;
    }
    Ok(())
}

pub fn decode_account_created(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountCreatedEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = WorldIdRegistry::AccountCreated::decode_log(&prim)?;

    // TODO: Validate pubkey is valid affine compressed
    Ok(AccountCreatedEvent {
        leaf_index: typed.data.leafIndex,
        recovery_address: typed.data.recoveryAddress,
        authenticator_addresses: typed.data.authenticatorAddresses,
        authenticator_pubkeys: typed.data.authenticatorPubkeys,
        offchain_signer_commitment: typed.data.offchainSignerCommitment,
    })
}

pub fn decode_account_updated(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountUpdatedEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = WorldIdRegistry::AccountUpdated::decode_log(&prim)?;

    Ok(AccountUpdatedEvent {
        leaf_index: typed.data.leafIndex,
        pubkey_id: typed.data.pubkeyId,
        new_authenticator_pubkey: typed.data.newAuthenticatorPubkey,
        old_authenticator_address: typed.data.oldAuthenticatorAddress,
        new_authenticator_address: typed.data.newAuthenticatorAddress,
        old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
        new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
    })
}

pub fn decode_authenticator_inserted(
    lg: &alloy::rpc::types::Log,
) -> anyhow::Result<AuthenticatorInsertedEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = WorldIdRegistry::AuthenticatorInserted::decode_log(&prim)?;

    Ok(AuthenticatorInsertedEvent {
        leaf_index: typed.data.leafIndex,
        pubkey_id: typed.data.pubkeyId,
        authenticator_address: typed.data.authenticatorAddress,
        new_authenticator_pubkey: typed.data.newAuthenticatorPubkey,
        old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
        new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
    })
}

pub fn decode_authenticator_removed(
    lg: &alloy::rpc::types::Log,
) -> anyhow::Result<AuthenticatorRemovedEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = WorldIdRegistry::AuthenticatorRemoved::decode_log(&prim)?;

    Ok(AuthenticatorRemovedEvent {
        leaf_index: typed.data.leafIndex,
        pubkey_id: typed.data.pubkeyId,
        authenticator_address: typed.data.authenticatorAddress,
        authenticator_pubkey: typed.data.authenticatorPubkey,
        old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
        new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
    })
}

pub fn decode_account_recovered(
    lg: &alloy::rpc::types::Log,
) -> anyhow::Result<AccountRecoveredEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = WorldIdRegistry::AccountRecovered::decode_log(&prim)?;

    Ok(AccountRecoveredEvent {
        leaf_index: typed.data.leafIndex,
        new_authenticator_address: typed.data.newAuthenticatorAddress,
        new_authenticator_pubkey: typed.data.newAuthenticatorPubkey,
        old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
        new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
    })
}

pub fn decode_registry_event(lg: &alloy::rpc::types::Log) -> anyhow::Result<RegistryEvent> {
    if lg.topics().is_empty() {
        anyhow::bail!("log has no topics");
    }

    let event_sig = lg.topics()[0];

    if event_sig == WorldIdRegistry::AccountCreated::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountCreated(decode_account_created(lg)?))
    } else if event_sig == WorldIdRegistry::AccountUpdated::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountUpdated(decode_account_updated(lg)?))
    } else if event_sig == WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH {
        Ok(RegistryEvent::AuthenticatorInserted(
            decode_authenticator_inserted(lg)?,
        ))
    } else if event_sig == WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH {
        Ok(RegistryEvent::AuthenticatorRemoved(
            decode_authenticator_removed(lg)?,
        ))
    } else if event_sig == WorldIdRegistry::AccountRecovered::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountRecovered(decode_account_recovered(
            lg,
        )?))
    } else {
        anyhow::bail!("unknown event signature: {event_sig:?}")
    }
}

pub async fn insert_account(
    pool: &PgPool,
    ev: &AccountCreatedEvent,
    block_number: u64,
) -> anyhow::Result<()> {
    let block_num = block_number as i64;
    sqlx::query(
        r#"insert into accounts
        (leaf_index, recovery_address, authenticator_addresses, authenticator_pubkeys, offchain_signer_commitment, last_updated_block)
        values ($1, $2, $3, $4, $5, $6)
        on conflict (leaf_index) do nothing"#,
    )
    .bind(ev.leaf_index.to_string())
    .bind(ev.recovery_address.to_string())
    .bind(Json(
        ev.authenticator_addresses
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>(),
    ))
    .bind(Json(
        ev.authenticator_pubkeys
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>(),
    ))
    .bind(ev.offchain_signer_commitment.to_string())
    .bind(block_num)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_commitment(
    pool: &PgPool,
    leaf_index: U256,
    new_commitment: U256,
    block_number: u64,
) -> anyhow::Result<()> {
    let block_num = block_number as i64;
    sqlx::query(
        r#"update accounts
        set offchain_signer_commitment = $2, last_updated_block = $3
        where leaf_index = $1 and (last_updated_block is null or last_updated_block < $3)"#,
    )
    .bind(leaf_index.to_string())
    .bind(new_commitment.to_string())
    .bind(block_num)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_authenticator_at_index(
    pool: &PgPool,
    leaf_index: U256,
    pubkey_id: u32,
    new_address: Address,
    new_pubkey: U256,
    new_commitment: U256,
    block_number: u64,
) -> anyhow::Result<()> {
    // Update authenticator at specific index (pubkey_id)
    // Enforce that last_updated_block must increase
    let block_num = block_number as i64;
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), false),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), false),
            offchain_signer_commitment = $5,
            last_updated_block = $6
        where leaf_index = $1 and (last_updated_block is null or last_updated_block < $6)"#,
    )
    .bind(leaf_index.to_string())
    .bind(format!("{{{pubkey_id}}}")) // JSONB path format: {0}, {1}, etc
    .bind(new_address.to_string())
    .bind(new_pubkey.to_string())
    .bind(new_commitment.to_string())
    .bind(block_num)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_authenticator_at_index(
    pool: &PgPool,
    leaf_index: U256,
    pubkey_id: u32,
    new_address: Address,
    new_pubkey: U256,
    new_commitment: U256,
    block_number: u64,
) -> anyhow::Result<()> {
    // Ensure arrays are large enough and insert at specific index
    // Enforce that last_updated_block must increase
    let block_num = block_number as i64;
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), true),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), true),
            offchain_signer_commitment = $5,
            last_updated_block = $6
        where leaf_index = $1 and (last_updated_block is null or last_updated_block < $6)"#,
    )
    .bind(leaf_index.to_string())
    .bind(format!("{{{pubkey_id}}}"))
    .bind(new_address.to_string())
    .bind(new_pubkey.to_string())
    .bind(new_commitment.to_string())
    .bind(block_num)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_authenticator_at_index(
    pool: &PgPool,
    leaf_index: U256,
    pubkey_id: u32,
    new_commitment: U256,
    block_number: u64,
) -> anyhow::Result<()> {
    // Remove authenticator at specific index by setting to null
    // Enforce that last_updated_block must increase
    let block_num = block_number as i64;
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, 'null'::jsonb, false),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, 'null'::jsonb, false),
            offchain_signer_commitment = $3,
            last_updated_block = $4
        where leaf_index = $1 and (last_updated_block is null or last_updated_block < $4)"#,
    )
    .bind(leaf_index.to_string())
    .bind(format!("{{{pubkey_id}}}"))
    .bind(new_commitment.to_string())
    .bind(block_num)
    .execute(pool)
    .await?;
    Ok(())
}

/// Check if an event has already been processed by querying commitment_update_events.
/// Returns true if the event exists (already processed), false otherwise.
async fn is_event_already_processed(
    pool: &PgPool,
    tx_hash: &alloy::primitives::B256,
    log_index: u64,
) -> anyhow::Result<bool> {
    let tx_str = format!("{tx_hash:?}");
    let exists: Option<(i64,)> = sqlx::query_as(
        "select 1 from commitment_update_events where tx_hash = $1 and log_index = $2 limit 1",
    )
    .bind(&tx_str)
    .bind(log_index as i64)
    .fetch_optional(pool)
    .await?;

    Ok(exists.is_some())
}

pub async fn record_commitment_update(
    pool: &PgPool,
    leaf_index: U256,
    event_type: &str,
    new_commitment: U256,
    block_number: u64,
    tx_hash: &str,
    log_index: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"insert into commitment_update_events
        (leaf_index, event_type, new_commitment, block_number, tx_hash, log_index)
        values ($1, $2, $3, $4, $5, $6)
        on conflict (tx_hash, log_index) do nothing"#,
    )
    .bind(leaf_index.to_string())
    .bind(event_type)
    .bind(new_commitment.to_string())
    .bind(block_number as i64)
    .bind(tx_hash)
    .bind(log_index as i64)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn handle_registry_event(
    pool: &PgPool,
    event: &RegistryEvent,
    block_number: u64,
    tx_hash: Option<alloy::primitives::B256>,
    log_index: Option<u64>,
) -> anyhow::Result<()> {
    match event {
        RegistryEvent::AccountCreated(ev) => {
            insert_account(pool, ev, block_number).await?;
            if let (Some(tx), Some(li)) = (tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "created",
                    ev.offchain_signer_commitment,
                    block_number,
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
                block_number,
            )
            .await?;
            if let (Some(tx), Some(li)) = (tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "updated",
                    ev.new_offchain_signer_commitment,
                    block_number,
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
                block_number,
            )
            .await?;
            if let (Some(tx), Some(li)) = (tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "inserted",
                    ev.new_offchain_signer_commitment,
                    block_number,
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
                block_number,
            )
            .await?;
            if let (Some(tx), Some(li)) = (tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "removed",
                    ev.new_offchain_signer_commitment,
                    block_number,
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
                block_number,
            )
            .await?;
            if let (Some(tx), Some(li)) = (tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.leaf_index,
                    "recovered",
                    ev.new_offchain_signer_commitment,
                    block_number,
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

async fn fetch_recent_account_updates(
    pool: &PgPool,
    since: std::time::SystemTime,
) -> anyhow::Result<Vec<(U256, U256)>> {
    // Convert SystemTime to timestamp
    let since_duration = since
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let since_timestamp = since_duration.as_secs() as i64;

    // Query commitment_update_events for recent changes
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (leaf_index)
            leaf_index,
            new_commitment
        FROM commitment_update_events
        WHERE created_at > to_timestamp($1)
        ORDER BY leaf_index, created_at DESC
        "#,
    )
    .bind(since_timestamp)
    .fetch_all(pool)
    .await?;

    let mut updates = Vec::new();
    for row in rows {
        let leaf_index_str: String = row.try_get("leaf_index")?;
        let commitment_str: String = row.try_get("new_commitment")?;

        if let (Ok(idx), Ok(comm)) = (
            leaf_index_str.parse::<U256>(),
            commitment_str.parse::<U256>(),
        ) {
            updates.push((idx, comm));
        }
    }

    Ok(updates)
}

/// Continuously indexes from the last saved checkpoint.
/// This task runs in a loop, periodically checking for new blocks and catching up.
/// Fetches the starting block from checkpoint inside the loop.
/// Uses checkpoint as the source of truth and runs on a 1-second interval.
/// All database updates are dedup-safe via conflict handling.
async fn index_task(
    rpc_url: &str,
    pool: &PgPool,
    registry_address: Address,
    start_block: Option<u64>,
    batch_size: u64,
    update_tree: bool,
) -> anyhow::Result<()> {
    const INTERVAL: Duration = Duration::from_secs(1);

    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().expect("invalid RPC URL"));

    // If start_block is defined do initial backfill from start_block
    if let Some(block) = start_block {
        let current_head = provider.get_block_number().await?;
        let mut from = block;
        let head = current_head;
        // If initial backfill_fails, error out. Don't retry indefinitely like the loop below.
        backfill_batch(
            &provider,
            pool,
            registry_address,
            &mut from,
            batch_size,
            update_tree,
            head,
        )
        .await?;
    }

    // Main loop: always use checkpoint as source of truth
    loop {
        // Step 1: Get last processed block from checkpoint
        let last_processed = match load_checkpoint(pool).await {
            Ok(Some(block)) => {
                tracing::debug!(block, "index task: loaded checkpoint");
                block
            }
            Ok(None) => {
                tracing::info!("index task: no checkpoint found, starting from block 1");
                1
            }
            Err(e) => {
                tracing::error!(?e, "index task: failed to load checkpoint, will retry");
                tokio::time::sleep(INTERVAL).await;
                continue;
            }
        };

        // Step 2: Get current chain head
        let current_head = match provider.get_block_number().await {
            Ok(head) => head,
            Err(e) => {
                tracing::error!(
                    ?e,
                    "index task: failed to get current chain head, will retry"
                );
                tokio::time::sleep(INTERVAL).await;
                continue;
            }
        };

        // Step 3: If we're behind, process one batch
        if last_processed < current_head {
            tracing::info!(
                from = last_processed,
                to = current_head,
                "index task: processing batch"
            );
            let mut from = last_processed;

            if let Err(err) = backfill_batch(
                &provider,
                pool,
                registry_address,
                &mut from,
                batch_size,
                update_tree,
                current_head,
            )
            .await
            {
                tracing::error!(?err, "index task: failed to backfill batch, will retry");
                tokio::time::sleep(INTERVAL).await;
                continue;
            }
        } else {
            tracing::debug!(
                last_processed,
                current_head,
                "index task: already caught up"
            );
        }

        // Wait before next check
        tokio::time::sleep(INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use alloy::uint;
    use semaphore_rs_trees::Branch;

    use super::*;

    #[test]
    fn test_poseidon2_merkle_tree() {
        let tree = MerkleTree::<PoseidonHasher>::new(10, U256::ZERO);
        let proof = tree.proof(0);
        let proof = proof.0.iter().collect::<Vec<_>>();
        assert!(
            *proof[1]
                == Branch::Left(uint!(
                15621590199821056450610068202457788725601603091791048810523422053872049975191_U256
            ))
        );
    }
}
