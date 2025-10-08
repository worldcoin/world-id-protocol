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
use semaphore_rs_trees::imt::MerkleTree;
use semaphore_rs_trees::proof::InclusionProof;
use semaphore_rs_trees::Branch;
use sqlx::{postgres::PgPoolOptions, types::Json, PgPool, Row};
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use world_id_core::account_registry::AccountRegistry;
use world_id_core::types::InclusionProofResponse;

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

#[derive(Clone, Debug)]
pub struct IndexerConfig {
    pub rpc_url: String,
    pub ws_url: String,
    pub registry_address: Address,
    pub db_url: String,
    pub start_block: u64,
    pub batch_size: u64,
    pub http_addr: SocketAddr,
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

// Big tree is too slow for debug builds, so we use a smaller tree
const TREE_DEPTH: usize = if cfg!(debug_assertions) { 10 } else { 30 };

// Global Merkle tree (singleton). Protected by an async RwLock for concurrent reads.
static GLOBAL_TREE: LazyLock<RwLock<MerkleTree<PoseidonHasher>>> =
    LazyLock::new(|| RwLock::new(MerkleTree::<PoseidonHasher>::new(TREE_DEPTH, U256::ZERO)));

async fn set_leaf_at_index(leaf_index: usize, value: U256) {
    let mut tree = GLOBAL_TREE.write().await;
    if leaf_index >= tree.num_leaves() {
        // Out of range for fixed depth tree
        tracing::error!(
            leaf_index,
            capacity = tree.num_leaves(),
            "leaf index out of range"
        );
        return;
    }
    tree.set(leaf_index, value);
}

async fn build_tree_from_db(pool: &PgPool) -> anyhow::Result<()> {
    let rows =
        sqlx::query("select account_index, offchain_signer_commitment from accounts order by account_index asc")
            .fetch_all(pool)
            .await?;

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

    let mut tree = GLOBAL_TREE.write().await;
    tree.set_range(0, leaves.into_iter().map(|(_, v)| v));
    tracing::info!(root = %format!("0x{:x}", tree.root()), depth = 30, "tree built from DB");
    Ok(())
}

async fn update_tree_with_commitment(account_index: U256, new_commitment: U256) -> anyhow::Result<()> {
    if account_index == 0 {
        anyhow::bail!("account index cannot be zero");
    }
    let leaf_index = account_index.as_limbs()[0] as usize - 1;
    set_leaf_at_index(leaf_index, new_commitment).await;
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
    .bind(&account_index.to_string())
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
    let tree = GLOBAL_TREE.read().await;
    match tree.proof(leaf_index) {
        Some(proof) => {
            let resp = InclusionProofResponse::new(
                account_index.as_limbs()[0],
                leaf_index as u64,
                tree.root(),
                proof_to_vec(&proof),
                authenticator_pubkeys,
            );
            (axum::http::StatusCode::OK, axum::Json(resp)).into_response()
        }
        None => (
            axum::http::StatusCode::BAD_REQUEST,
            "leaf index out of range",
        )
            .into_response(),
    }
}

async fn start_http_server(addr: SocketAddr, pool: PgPool) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .route("/proof/:account_index", axum::routing::get(http_get_proof))
        .with_state(pool);

    tracing::info!(%addr, "HTTP server listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

pub async fn run_from_env() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "authtree_indexer=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let _ = dotenvy::dotenv();

    let cfg = load_config_from_env();
    tracing::info!(?cfg, "starting authtree-indexer");

    run_indexer(cfg).await
}

pub fn load_config_from_env() -> IndexerConfig {
    use alloy::primitives::address;
    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string());
    let registry_address = std::env::var("REGISTRY_ADDRESS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| address!("0x0000000000000000000000000000000000000000"));
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());
    let start_block: u64 = std::env::var("START_BLOCK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let batch_size: u64 = std::env::var("BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let ws_url = std::env::var("WS_URL").unwrap_or_else(|_| "ws://localhost:8545".to_string());
    let http_addr = std::env::var("HTTP_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "0.0.0.0:8080".parse().unwrap());
    IndexerConfig {
        rpc_url,
        ws_url,
        registry_address,
        db_url,
        start_block,
        batch_size,
        http_addr,
    }
}

pub async fn run_indexer(cfg: IndexerConfig) -> anyhow::Result<()> {
    let provider =
        ProviderBuilder::new().connect_http(cfg.rpc_url.parse().expect("invalid RPC URL"));

    let pool = make_db_pool(&cfg.db_url).await?;
    init_db(&pool).await?;

    let start_time = std::time::Instant::now();
    build_tree_from_db(&pool).await?;
    tracing::info!("building tree from DB took {:?}", start_time.elapsed());

    // Start HTTP server
    let http_pool = pool.clone();
    let http_addr = cfg.http_addr;
    let http_handle = tokio::spawn(async move { start_http_server(http_addr, http_pool).await });

    // Determine starting block from checkpoint or env
    let mut from = load_checkpoint(&pool).await?.unwrap_or(cfg.start_block);

    // Backfill until head
    loop {
        if let Err(err) = backfill(
            &provider,
            &pool,
            cfg.registry_address,
            &mut from,
            cfg.batch_size,
        )
        .await
        {
            tracing::error!(?err, "backfill error; retrying after delay");
            tokio::time::sleep(Duration::from_secs(5)).await;
        } else {
            break;
        }
    }

    tracing::info!("switching to websocket live follow");
    stream_logs(&cfg.ws_url, &pool, cfg.registry_address, from).await?;

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

pub async fn backfill<P: Provider>(
    provider: &P,
    pool: &PgPool,
    registry: Address,
    from_block: &mut u64,
    batch_size: u64,
) -> anyhow::Result<()> {
    // Determine current head
    let head: u64 = provider.get_block_number().await?.into();
    if *from_block == 0 {
        *from_block = 1;
    }
    if *from_block > head {
        return Ok(());
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
                tracing::info!(?event, "decoded registry event");
                let block_number = lg.block_number;
                let tx_hash = lg.transaction_hash;
                let log_index = lg.log_index;
                
                if let Err(e) = handle_registry_event(pool, &event, block_number, tx_hash, log_index).await {
                    tracing::error!(?e, ?event, "failed to handle registry event in DB");
                }
                
                if let Err(e) = update_tree_with_event(&event).await {
                    tracing::error!(?e, ?event, "failed to update tree for event");
                }
            }
            Err(e) => {
                tracing::warn!(?e, ?lg, "failed to decode registry event");
            }
        }
    }

    save_checkpoint(pool, to_block).await?;
    *from_block = to_block + 1;
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

pub fn decode_authenticator_inserted(lg: &alloy::rpc::types::Log) -> anyhow::Result<AuthenticatorInsertedEvent> {
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

pub fn decode_authenticator_removed(lg: &alloy::rpc::types::Log) -> anyhow::Result<AuthenticatorRemovedEvent> {
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

pub fn decode_account_recovered(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountRecoveredEvent> {
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
        Ok(RegistryEvent::AuthenticatorInserted(decode_authenticator_inserted(lg)?))
    } else if event_sig == AccountRegistry::AuthenticatorRemoved::SIGNATURE_HASH {
        Ok(RegistryEvent::AuthenticatorRemoved(decode_authenticator_removed(lg)?))
    } else if event_sig == AccountRegistry::AccountRecovered::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountRecovered(decode_account_recovered(lg)?))
    } else {
        anyhow::bail!("unknown event signature: {:?}", event_sig)
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

pub async fn stream_logs(
    ws_url: &str,
    pool: &PgPool,
    registry: Address,
    start_from: u64,
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
                
                if let Err(e) = handle_registry_event(pool, &event, block_number, tx_hash, log_index).await {
                    tracing::error!(?e, ?event, "failed to handle registry event in DB");
                }
                
                if let Err(e) = update_tree_with_event(&event).await {
                    tracing::error!(?e, ?event, "failed to update tree for live event");
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
        let proof = tree.proof(0).unwrap();
        let proof = proof.0.iter().collect::<Vec<_>>();
        let poseidon00 = uint!(
            15621590199821056450610068202457788725601603091791048810523422053872049975191_U256
        );
        assert_eq!(*proof[1], Branch::Left(poseidon00));
    }
}
