use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;

use alloy::primitives::{Address, Log, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use ark_bn254::Fr;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T2_PARAMS};
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use semaphore_rs_trees::proof::InclusionProof;
use semaphore_rs_trees::Branch;
use sqlx::migrate::Migrator;
use sqlx::{postgres::PgPoolOptions, types::Json, PgPool, Row};
use tokio::sync::RwLock;
use world_id_core::account_registry::AccountRegistry;
use world_id_primitives::{
    authenticator::MAX_AUTHENTICATOR_KEYS,
    merkle::{AccountInclusionProof, MerkleInclusionProof},
    FieldElement, TREE_DEPTH,
};

mod config;
use crate::config::{HttpConfig, IndexerConfig, RunMode};
pub use config::GlobalConfig;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone)]
pub struct AccountCreatedEvent {
    pub account_index: U256,
    pub recovery_address: Address,
    pub authenticator_addresses: Vec<Address>,
    pub authenticator_pubkeys: Vec<U256>,
    pub offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AccountUpdatedEvent {
    pub account_index: U256,
    pub pubkey_id: U256,
    pub new_authenticator_pubkey: U256,
    pub old_authenticator_address: Address,
    pub new_authenticator_address: Address,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorInsertedEvent {
    pub account_index: U256,
    pub pubkey_id: U256,
    pub authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorRemovedEvent {
    pub account_index: U256,
    pub pubkey_id: U256,
    pub authenticator_address: Address,
    pub authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AccountRecoveredEvent {
    pub account_index: U256,
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
static GLOBAL_TREE: LazyLock<RwLock<MerkleTree<PoseidonHasher, Canonical>>> =
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
        "select account_index, offchain_signer_commitment from accounts order by account_index asc",
    )
    .fetch_all(pool)
    .await?;

    tracing::info!("There are {:?} rows in the table.", rows.len());

    let mut leaves: Vec<(usize, U256)> = Vec::with_capacity(rows.len());
    for r in rows {
        let account_index: String = r.get("account_index");
        let offchain: String = r.get("offchain_signer_commitment");
        let account_index: U256 = account_index.parse::<U256>()?;
        if account_index == U256::ZERO {
            continue;
        }
        let leaf_index = account_index.as_limbs()[0] as usize - 1;
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

async fn update_tree_with_commitment(
    account_index: U256,
    new_commitment: U256,
) -> anyhow::Result<()> {
    if account_index == 0 {
        anyhow::bail!("account index cannot be zero");
    }
    let leaf_index = account_index.as_limbs()[0] as usize - 1;
    set_leaf_at_index(leaf_index, new_commitment).await?;
    Ok(())
}

async fn update_tree_with_event(ev: &RegistryEvent) -> anyhow::Result<()> {
    match ev {
        RegistryEvent::AccountCreated(e) => {
            update_tree_with_commitment(e.account_index, e.offchain_signer_commitment).await
        }
        RegistryEvent::AccountUpdated(e) => {
            update_tree_with_commitment(e.account_index, e.new_offchain_signer_commitment).await
        }
        RegistryEvent::AuthenticatorInserted(e) => {
            update_tree_with_commitment(e.account_index, e.new_offchain_signer_commitment).await
        }
        RegistryEvent::AuthenticatorRemoved(e) => {
            update_tree_with_commitment(e.account_index, e.new_offchain_signer_commitment).await
        }
        RegistryEvent::AccountRecovered(e) => {
            update_tree_with_commitment(e.account_index, e.new_offchain_signer_commitment).await
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

async fn http_get_proof(
    Path(idx_str): Path<String>,
    State(pool): State<PgPool>,
) -> impl axum::response::IntoResponse {
    let account_index: U256 = idx_str.parse().unwrap();
    if account_index == 0 {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid account index").into_response();
    }

    let account_row = sqlx::query(
        "select offchain_signer_commitment, authenticator_pubkeys from accounts where account_index = $1",
    )
    .bind(account_index.to_string())
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    if account_row.is_none() {
        return (axum::http::StatusCode::NOT_FOUND, "account not found").into_response();
    }

    let row = account_row.unwrap();
    let pubkeys_json: Json<Vec<String>> = row.get("authenticator_pubkeys");
    let authenticator_pubkeys: Vec<U256> = pubkeys_json
        .0
        .iter()
        .filter_map(|s| s.parse::<U256>().ok())
        .collect();

    let leaf_index = account_index.as_limbs()[0] as usize - 1;
    if leaf_index >= tree_capacity() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "leaf index out of range",
        )
            .into_response();
    }
    // Validate the number of authenticator keys
    if authenticator_pubkeys.len() > MAX_AUTHENTICATOR_KEYS {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Account has {} authenticator keys, which exceeds the maximum of {}",
                authenticator_pubkeys.len(),
                MAX_AUTHENTICATOR_KEYS
            ),
        )
            .into_response();
    }

    let tree = GLOBAL_TREE.read().await;
    let proof = tree.proof(leaf_index);

    // Convert proof siblings to FieldElement array
    let siblings_vec: Vec<FieldElement> = proof_to_vec(&proof)
        .into_iter()
        .map(|u| u.try_into().unwrap())
        .collect();
    let siblings: [FieldElement; TREE_DEPTH] = siblings_vec.try_into().unwrap();

    let merkle_proof = MerkleInclusionProof::new(
        tree.root().try_into().unwrap(),
        leaf_index as u64,
        account_index.as_limbs()[0],
        siblings,
    );

    let resp = AccountInclusionProof::new(merkle_proof, authenticator_pubkeys)
        .expect("authenticator_pubkeys already validated");
    (axum::http::StatusCode::OK, axum::Json(resp)).into_response()
}

async fn http_health() -> impl IntoResponse {
    // TODO: check DB connection
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({"status":"ok"})),
    )
}

async fn start_http_server(addr: SocketAddr, pool: PgPool) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .route("/proof/:account_index", axum::routing::get(http_get_proof))
        .route("/health", axum::routing::get(http_health))
        .with_state(pool);

    tracing::info!(%addr, "HTTP server listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

/// Periodically checks that the local in-memory Merkle root remains valid on-chain.
async fn root_sanity_check_loop(
    rpc_url: String,
    registry: Address,
    interval_secs: u64,
) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().expect("invalid RPC URL"));
    let contract = AccountRegistry::new(registry, provider.clone());

    tracing::info!(
        registry = %registry,
        interval_secs,
        "Starting periodic Merkle root sanity checker"
    );

    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        // Read local root under read lock
        let local_root = { GLOBAL_TREE.read().await.root() };

        // Check validity window on-chain first (covers slight lag vs current root)
        let is_valid = match contract.isValidRoot(local_root).call().await {
            Ok(v) => v,
            Err(err) => {
                tracing::error!(?err, "failed to call isValidRoot");
                continue;
            }
        };

        if !is_valid {
            // Fetch current on-chain root for diagnostics
            let current_onchain_root = match contract.currentRoot().call().await {
                Ok(r) => r,
                Err(err) => {
                    tracing::error!(?err, "failed to call currentRoot");
                    U256::ZERO
                }
            };

            tracing::error!(
                local_root = %format!("0x{:x}", local_root),
                current_onchain_root = %format!("0x{:x}", current_onchain_root),
                "Local Merkle root is not valid on-chain"
            );
        } else {
            tracing::debug!(local_root = %format!("0x{:x}", local_root), "Local Merkle root is valid on-chain");
        }
    }
}

pub async fn run_indexer(cfg: GlobalConfig) -> anyhow::Result<()> {
    let pool = make_db_pool(&cfg.db_url).await?;
    init_db(&pool).await?;

    tracing::info!("Connection to DB successful, running migrations.");
    MIGRATOR.run(&pool).await.expect("failed to run migrations");
    tracing::info!("🟢 Migrations synced successfully.");

    match cfg.run_mode {
        RunMode::IndexerOnly { indexer_config } => {
            tracing::info!("Running in INDEXER-ONLY mode (no in-memory tree)");
            run_indexer_only(indexer_config, pool).await
        }
        RunMode::HttpOnly { http_config } => {
            tracing::info!("Running in HTTP-ONLY mode (building tree from DB)");
            // Build tree from DB for HTTP-only mode
            let start_time = std::time::Instant::now();
            build_tree_from_db(&pool).await?;
            tracing::info!("building tree from DB took {:?}", start_time.elapsed());
            run_http_only(http_config, pool).await
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
            run_both(indexer_config, http_config, pool).await
        }
    }
}

async fn run_indexer_only(indexer_cfg: IndexerConfig, pool: PgPool) -> anyhow::Result<()> {
    let provider =
        ProviderBuilder::new().connect_http(indexer_cfg.rpc_url.parse().expect("invalid RPC URL"));

    // Determine starting block from checkpoint or env
    let mut from = load_checkpoint(&pool)
        .await?
        .unwrap_or(indexer_cfg.start_block);

    // Backfill until head (update_tree = false for indexer-only mode)
    backfill(
        &provider,
        &pool,
        indexer_cfg.registry_address,
        &mut from,
        indexer_cfg.batch_size,
        false, // Don't update in-memory tree
    )
    .await?;

    tracing::info!("switching to websocket live follow");
    stream_logs(
        &indexer_cfg.ws_url,
        &pool,
        indexer_cfg.registry_address,
        from,
        false,
    )
    .await?;

    Ok(())
}

async fn run_http_only(http_cfg: HttpConfig, pool: PgPool) -> anyhow::Result<()> {
    // Start DB poller for account updates
    let poller_pool = pool.clone();
    let poll_interval = http_cfg.db_poll_interval_secs;
    let poller_handle = tokio::spawn(async move {
        if let Err(e) = poll_db_changes(poller_pool, poll_interval).await {
            tracing::error!(?e, "DB poller failed");
        }
    });

    // Start HTTP server
    let http_result = start_http_server(http_cfg.http_addr, pool).await;

    poller_handle.abort();
    http_result
}

async fn run_both(
    indexer_cfg: IndexerConfig,
    http_cfg: HttpConfig,
    pool: PgPool,
) -> anyhow::Result<()> {
    let provider =
        ProviderBuilder::new().connect_http(indexer_cfg.rpc_url.parse().expect("invalid RPC URL"));

    // Start HTTP server
    let http_pool = pool.clone();
    let http_addr = http_cfg.http_addr;
    let http_handle = tokio::spawn(async move { start_http_server(http_addr, http_pool).await });

    // Start root sanity checker in the background
    let sanity_rpc_url = indexer_cfg.rpc_url.clone();
    let sanity_registry = indexer_cfg.registry_address;
    let sanity_interval = indexer_cfg.sanity_check_interval_secs;
    let _sanity_handle = tokio::spawn(async move {
        if let Err(e) =
            root_sanity_check_loop(sanity_rpc_url, sanity_registry, sanity_interval).await
        {
            tracing::error!(?e, "Root sanity checker failed");
        }
    });

    // Determine starting block from checkpoint or env
    let mut from = load_checkpoint(&pool)
        .await?
        .unwrap_or(indexer_cfg.start_block);

    // Backfill until head (update_tree = true for both mode)
    backfill(
        &provider,
        &pool,
        indexer_cfg.registry_address,
        &mut from,
        indexer_cfg.batch_size,
        true, // Update in-memory tree directly from events
    )
    .await?;

    tracing::info!("switching to websocket live follow");
    stream_logs(
        &indexer_cfg.ws_url,
        &pool,
        indexer_cfg.registry_address,
        from,
        true,
    )
    .await?;

    http_handle.abort();
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
    sqlx::query(
        "insert into checkpoints (name, last_block) values ($1, $2) on conflict (name) do update set last_block = excluded.last_block",
    )
    .bind("account_created")
    .bind(block as i64)
    .execute(pool)
    .await?;
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
        AccountRegistry::AccountCreated::SIGNATURE_HASH,
        AccountRegistry::AccountUpdated::SIGNATURE_HASH,
        AccountRegistry::AuthenticatorInserted::SIGNATURE_HASH,
        AccountRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
        AccountRegistry::AccountRecovered::SIGNATURE_HASH,
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

pub fn decode_account_created(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountCreatedEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = AccountRegistry::AccountCreated::decode_log(&prim)?;

    Ok(AccountCreatedEvent {
        account_index: typed.data.accountIndex,
        recovery_address: typed.data.recoveryAddress,
        authenticator_addresses: typed.data.authenticatorAddresses,
        authenticator_pubkeys: typed.data.authenticatorPubkeys,
        offchain_signer_commitment: typed.data.offchainSignerCommitment,
    })
}

pub fn decode_account_updated(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountUpdatedEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = AccountRegistry::AccountUpdated::decode_log(&prim)?;

    Ok(AccountUpdatedEvent {
        account_index: typed.data.accountIndex,
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
    let typed = AccountRegistry::AuthenticatorInserted::decode_log(&prim)?;

    Ok(AuthenticatorInsertedEvent {
        account_index: typed.data.accountIndex,
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
    let typed = AccountRegistry::AuthenticatorRemoved::decode_log(&prim)?;

    Ok(AuthenticatorRemovedEvent {
        account_index: typed.data.accountIndex,
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
    let typed = AccountRegistry::AccountRecovered::decode_log(&prim)?;

    Ok(AccountRecoveredEvent {
        account_index: typed.data.accountIndex,
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

    if event_sig == AccountRegistry::AccountCreated::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountCreated(decode_account_created(lg)?))
    } else if event_sig == AccountRegistry::AccountUpdated::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountUpdated(decode_account_updated(lg)?))
    } else if event_sig == AccountRegistry::AuthenticatorInserted::SIGNATURE_HASH {
        Ok(RegistryEvent::AuthenticatorInserted(
            decode_authenticator_inserted(lg)?,
        ))
    } else if event_sig == AccountRegistry::AuthenticatorRemoved::SIGNATURE_HASH {
        Ok(RegistryEvent::AuthenticatorRemoved(
            decode_authenticator_removed(lg)?,
        ))
    } else if event_sig == AccountRegistry::AccountRecovered::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountRecovered(decode_account_recovered(
            lg,
        )?))
    } else {
        anyhow::bail!("unknown event signature: {event_sig:?}")
    }
}

pub async fn insert_account(pool: &PgPool, ev: &AccountCreatedEvent) -> anyhow::Result<()> {
    sqlx::query(
        r#"insert into accounts
        (account_index, recovery_address, authenticator_addresses, authenticator_pubkeys, offchain_signer_commitment)
        values ($1, $2, $3, $4, $5)
        on conflict (account_index) do nothing"#,
    )
    .bind(ev.account_index.to_string())
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
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_commitment(
    pool: &PgPool,
    account_index: U256,
    new_commitment: U256,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"update accounts
        set offchain_signer_commitment = $2
        where account_index = $1"#,
    )
    .bind(account_index.to_string())
    .bind(new_commitment.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_authenticator_at_index(
    pool: &PgPool,
    account_index: U256,
    pubkey_id: u32,
    new_address: Address,
    new_pubkey: U256,
    new_commitment: U256,
) -> anyhow::Result<()> {
    // Update authenticator at specific index (pubkey_id)
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), false),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), false),
            offchain_signer_commitment = $5
        where account_index = $1"#,
    )
    .bind(account_index.to_string())
    .bind(format!("{{{}}}", pubkey_id)) // JSONB path format: {0}, {1}, etc
    .bind(new_address.to_string())
    .bind(new_pubkey.to_string())
    .bind(new_commitment.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_authenticator_at_index(
    pool: &PgPool,
    account_index: U256,
    pubkey_id: u32,
    new_address: Address,
    new_pubkey: U256,
    new_commitment: U256,
) -> anyhow::Result<()> {
    // Ensure arrays are large enough and insert at specific index
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), true),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), true),
            offchain_signer_commitment = $5
        where account_index = $1"#,
    )
    .bind(account_index.to_string())
    .bind(format!("{{{}}}", pubkey_id))
    .bind(new_address.to_string())
    .bind(new_pubkey.to_string())
    .bind(new_commitment.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_authenticator_at_index(
    pool: &PgPool,
    account_index: U256,
    pubkey_id: u32,
    new_commitment: U256,
) -> anyhow::Result<()> {
    // Remove authenticator at specific index by setting to null
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, 'null'::jsonb, false),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, 'null'::jsonb, false),
            offchain_signer_commitment = $3
        where account_index = $1"#,
    )
    .bind(account_index.to_string())
    .bind(format!("{{{}}}", pubkey_id))
    .bind(new_commitment.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn record_commitment_update(
    pool: &PgPool,
    account_index: U256,
    event_type: &str,
    new_commitment: U256,
    block_number: u64,
    tx_hash: &str,
    log_index: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"insert into commitment_update_events
        (account_index, event_type, new_commitment, block_number, tx_hash, log_index)
        values ($1, $2, $3, $4, $5, $6)
        on conflict (tx_hash, log_index) do nothing"#,
    )
    .bind(account_index.to_string())
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
                    ev.account_index,
                    "created",
                    ev.offchain_signer_commitment,
                    bn,
                    &format!("{:?}", tx),
                    li,
                )
                .await?;
            }
        }
        RegistryEvent::AccountUpdated(ev) => {
            let pubkey_id = ev.pubkey_id.to::<u32>();
            update_authenticator_at_index(
                pool,
                ev.account_index,
                pubkey_id,
                ev.new_authenticator_address,
                ev.new_authenticator_pubkey,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.account_index,
                    "updated",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{:?}", tx),
                    li,
                )
                .await?;
            }
        }
        RegistryEvent::AuthenticatorInserted(ev) => {
            let pubkey_id = ev.pubkey_id.to::<u32>();
            insert_authenticator_at_index(
                pool,
                ev.account_index,
                pubkey_id,
                ev.authenticator_address,
                ev.new_authenticator_pubkey,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.account_index,
                    "inserted",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{:?}", tx),
                    li,
                )
                .await?;
            }
        }
        RegistryEvent::AuthenticatorRemoved(ev) => {
            let pubkey_id = ev.pubkey_id.to::<u32>();
            remove_authenticator_at_index(
                pool,
                ev.account_index,
                pubkey_id,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.account_index,
                    "removed",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{:?}", tx),
                    li,
                )
                .await?;
            }
        }
        RegistryEvent::AccountRecovered(ev) => {
            // Recovery resets to a single authenticator at index 0
            update_authenticator_at_index(
                pool,
                ev.account_index,
                0,
                ev.new_authenticator_address,
                ev.new_authenticator_pubkey,
                ev.new_offchain_signer_commitment,
            )
            .await?;
            if let (Some(bn), Some(tx), Some(li)) = (block_number, tx_hash, log_index) {
                record_commitment_update(
                    pool,
                    ev.account_index,
                    "recovered",
                    ev.new_offchain_signer_commitment,
                    bn,
                    &format!("{:?}", tx),
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

                    for (account_index, commitment) in updates {
                        tracing::debug!(
                            account_index = %account_index,
                            commitment = %commitment,
                            "Updating tree from DB poll"
                        );

                        if let Err(e) = update_tree_with_commitment(account_index, commitment).await
                        {
                            tracing::error!(
                                ?e,
                                account_index = %account_index,
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
        SELECT DISTINCT ON (account_index)
            account_index,
            new_commitment
        FROM commitment_update_events
        WHERE created_at > to_timestamp($1)
        ORDER BY account_index, created_at DESC
        "#,
    )
    .bind(since_timestamp)
    .fetch_all(pool)
    .await?;

    let mut updates = Vec::new();
    for row in rows {
        let account_index_str: String = row.try_get("account_index")?;
        let commitment_str: String = row.try_get("new_commitment")?;

        if let (Ok(idx), Ok(comm)) = (
            account_index_str.parse::<U256>(),
            commitment_str.parse::<U256>(),
        ) {
            updates.push((idx, comm));
        }
    }

    Ok(updates)
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
        AccountRegistry::AccountCreated::SIGNATURE_HASH,
        AccountRegistry::AccountUpdated::SIGNATURE_HASH,
        AccountRegistry::AuthenticatorInserted::SIGNATURE_HASH,
        AccountRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
        AccountRegistry::AccountRecovered::SIGNATURE_HASH,
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
