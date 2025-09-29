use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use world_id_core::account_registry::AccountRegistry;
use world_id_core::ProofResponse;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T2_PARAMS};
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::imt::MerkleTree;
use semaphore_rs_trees::proof::InclusionProof;
use semaphore_rs_trees::Branch;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use axum::extract::{Path, State};
use axum::response::IntoResponse;

#[derive(Debug, Clone)]
pub struct DecodedAccountCreated {
    pub account_index_hex: String,
    pub recovery_address_bytes: String,
    pub authenticator_addresses_hex: Vec<String>,
    pub offchain_signer_commitment_hex: String,
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
        let left = Fr::from_le_bytes_mod_order(&left.to_le_bytes::<32>()[..]);
        let right = Fr::from_le_bytes_mod_order(&right.to_le_bytes::<32>()[..]);
        let mut input = [left, right];
        let feed_forward = input[0];
        POSEIDON_HASHER.permutation_in_place(&mut input);
        input[0] += feed_forward;
        U256::from_limbs(input[0].into_bigint().0)
    }
}

// Big tree is too slow for debug builds, so we use a smaller tree
const TREE_DEPTH: usize = if cfg!(debug_assertions) { 10 } else { 30 };

// Global Merkle tree (singleton). Protected by an async RwLock for concurrent reads.
static GLOBAL_TREE: LazyLock<RwLock<MerkleTree<PoseidonHasher>>> =
    LazyLock::new(|| RwLock::new(MerkleTree::<PoseidonHasher>::new(TREE_DEPTH, U256::ZERO)));

fn hex_to_u256(hex_str: &str) -> anyhow::Result<U256> {
    let s = hex_str.trim();
    Ok(s.parse()?)
}

fn hex_to_u64(hex_str: &str) -> anyhow::Result<u64> {
    let s = hex_str.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(u64::from_str_radix(s, 16)?)
}

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
    // Fetch all existing events (runtime-checked query to avoid sqlx offline prepare)
    let rows =
        sqlx::query("select account_index, offchain_signer_commitment from account_created_events")
            .fetch_all(pool)
            .await?;

    // Compute max index to size the tree
    let mut max_index: u64 = 0;
    let mut leaves: Vec<(usize, U256)> = Vec::with_capacity(rows.len());
    for r in rows {
        let account_index: String = r.get("account_index");
        let offchain: String = r.get("offchain_signer_commitment");
        let idx_u64 = hex_to_u64(&account_index)?;
        if idx_u64 == 0 {
            continue;
        }
        let leaf_index = (idx_u64 - 1) as usize;
        let leaf_val = hex_to_u256(&offchain)?;
        leaves.push((leaf_index, leaf_val));
        if idx_u64 > max_index {
            max_index = idx_u64;
        }
    }

    let mut tree = GLOBAL_TREE.write().await;
    tree.set_range(0, leaves.into_iter().map(|(_, v)| v));
    tracing::info!(root = %format!("0x{:x}", tree.root()), depth = 30, "tree built from DB");
    Ok(())
}

async fn update_tree_with_event(ev: &DecodedAccountCreated) -> anyhow::Result<()> {
    let idx = hex_to_u64(&ev.account_index_hex)?;
    if idx == 0 {
        anyhow::bail!("account index cannot be zero");
    }
    let leaf_index = (idx - 1) as usize;
    let value = hex_to_u256(&ev.offchain_signer_commitment_hex)?;
    set_leaf_at_index(leaf_index, value).await;
    Ok(())
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
    // Accept decimal or 0x-prefixed hex
    let account_index = if let Ok(v) = idx_str.parse::<u64>() {
        v
    } else if let Some(stripped) = idx_str.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).unwrap_or(0)
    } else {
        0
    };
    if account_index == 0 {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid account index").into_response();
    }

    // Check existence in DB to avoid returning proof for empty leaf
    let key_hex = format!("0x{:x}", account_index);
    let exists = sqlx::query_scalar::<_, String>(
        "select offchain_signer_commitment from account_created_events where account_index = $1",
    )
    .bind(&key_hex)
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();
    if exists.is_none() {
        return (axum::http::StatusCode::NOT_FOUND, "account not found").into_response();
    }

    let leaf_index = (account_index - 1) as usize;
    let tree = GLOBAL_TREE.read().await;
    match tree.proof(leaf_index) {
        Some(proof) => {
            let resp = ProofResponse::new(
                account_index,
                leaf_index as u64,
                tree.root(),
                proof_to_vec(&proof),
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

    let filter = Filter::new()
        .address(registry)
        .event_signature(AccountRegistry::AccountCreated::SIGNATURE_HASH)
        .from_block(*from_block)
        .to_block(to_block);

    let logs = provider.get_logs(&filter).await?;
    if !logs.is_empty() {
        tracing::info!(
            count = logs.len(),
            from = *from_block,
            to = to_block,
            "processing AccountCreated logs"
        );
    }
    for lg in logs {
        let decoded = decode_account_created(&lg)?;
        insert_account(pool, &decoded).await?;
        if let Err(e) = update_tree_with_event(&decoded).await {
            tracing::error!(?e, "failed to update tree for event");
        }
    }
    save_checkpoint(pool, to_block).await?;
    *from_block = to_block + 1;
    Ok(())
}

pub fn decode_account_created(
    lg: &alloy::rpc::types::Log,
) -> anyhow::Result<DecodedAccountCreated> {
    use alloy::primitives::Log as PLog;
    // Convert RPC log to primitives Log and use typed decoder
    let prim = PLog::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = AccountRegistry::AccountCreated::decode_log(&prim)?; // returns Log<AccountCreated>
    let ev = typed.data;

    let account_index_hex = format!("0x{:x}", ev.accountIndex);
    let recovery_address_bytes = format!("0x{:x}", ev.recoveryAddress);
    let authenticator_addresses_hex = ev
        .authenticatorAddresses
        .into_iter()
        .map(|a| format!("0x{:x}", a))
        .collect();
    let offchain_signer_commitment_hex = format!("0x{:x}", ev.offchainSignerCommitment);

    Ok(DecodedAccountCreated {
        account_index_hex,
        recovery_address_bytes,
        authenticator_addresses_hex,
        offchain_signer_commitment_hex,
    })
}

pub async fn insert_account(pool: &PgPool, ev: &DecodedAccountCreated) -> anyhow::Result<()> {
    let account_index = ev.account_index_hex.clone();
    let recovery_address = ev.recovery_address_bytes.clone();
    let auth_addrs_json = serde_json::Value::Array(
        ev.authenticator_addresses_hex
            .iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect(),
    );
    let offchain = ev.offchain_signer_commitment_hex.clone();

    sqlx::query(
        r#"insert into account_created_events
        (account_index, recovery_address, authenticator_addresses, offchain_signer_commitment)
        values ($1, $2, $3, $4)
        on conflict (account_index) do nothing"#,
    )
    .bind(account_index)
    .bind(recovery_address)
    .bind(auth_addrs_json)
    .bind(offchain)
    .execute(pool)
    .await?;
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
    let filter = Filter::new()
        .address(registry)
        .event_signature(AccountRegistry::AccountCreated::SIGNATURE_HASH)
        .from_block(start_from);
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();
    while let Some(log) = stream.next().await {
        if let Ok(decoded) = decode_account_created(&log) {
            tracing::info!(?decoded, "processing live AccountCreated log");
            insert_account(pool, &decoded).await?;
            if let Err(e) = update_tree_with_event(&decoded).await {
                tracing::error!(?e, "failed to update tree for live event");
            }
            if let Some(bn) = log.block_number {
                save_checkpoint(pool, bn).await?;
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
