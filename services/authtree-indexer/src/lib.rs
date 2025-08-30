use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use common::authenticator_registry::AuthenticatorRegistry;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone)]
pub struct DecodedAccountCreated {
    pub account_index_hex: String,
    pub recovery_address_bytes: Vec<u8>,
    pub authenticator_addresses_hex: Vec<String>,
    pub offchain_signer_commitment_hex: String,
}

#[derive(Clone, Debug)]
pub struct IndexerConfig {
    pub rpc_url: String,
    pub ws_url: Option<String>,
    pub registry_address: Address,
    pub db_url: String,
    pub start_block: u64,
    pub batch_size: u64,
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
    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL is required");
    let registry_address = std::env::var("REGISTRY_ADDRESS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| address!("0x0000000000000000000000000000000000000000"));
    let db_url = std::env::var("DATABASE_URL").or_else(|_| std::env::var("PG_URL")).expect("DATABASE_URL/PG_URL");
    let start_block: u64 = std::env::var("START_BLOCK").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let batch_size: u64 = std::env::var("BATCH_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(5_000);
    let ws_url = std::env::var("WS_URL").ok();
    IndexerConfig { rpc_url, ws_url, registry_address, db_url, start_block, batch_size }
}

pub async fn run_indexer(cfg: IndexerConfig) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new()
        .connect_http(cfg.rpc_url.parse().expect("invalid RPC URL"));

    let pool = make_db_pool(&cfg.db_url).await?;
    init_db(&pool).await?;

    // Determine starting block from checkpoint or env
    let mut from = load_checkpoint(&pool).await?.unwrap_or(cfg.start_block);

    // Backfill until head
    loop {
        if let Err(err) = backfill(&provider, &pool, cfg.registry_address, &mut from, cfg.batch_size).await {
            tracing::error!(?err, "backfill error; retrying after delay");
            tokio::time::sleep(Duration::from_secs(5)).await;
        } else {
            break;
        }
    }

    // After backfill, follow via WS if WS_URL is provided; otherwise end
    if let Some(ws_url) = cfg.ws_url {
        tracing::info!("switching to websocket live follow");
        stream_logs(&ws_url, &pool, cfg.registry_address, from).await?;
    }
    Ok(())
}

pub async fn make_db_pool(db_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new().max_connections(10).connect(db_url).await?;
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
    if *from_block == 0 { *from_block = 1; }
    if *from_block > head { return Ok(()); }

    let to_block = (*from_block + batch_size - 1).min(head);

    let topic0 = AuthenticatorRegistry::AccountCreated::SIGNATURE_HASH;

    let filter = Filter::new()
        .address(registry)
        .event_signature(topic0)
        .from_block(*from_block)
        .to_block(to_block);

    let logs = provider.get_logs(&filter).await?;
    if !logs.is_empty() {
        tracing::info!(count = logs.len(), from = *from_block, to = to_block, "processing AccountCreated logs");
    }
    for lg in logs {
        let decoded = decode_account_created(&lg)?;
        insert_account(pool, &decoded).await?;
    }
    save_checkpoint(pool, to_block).await?;
    *from_block = to_block + 1;
    Ok(())
}

pub fn decode_account_created(lg: &alloy::rpc::types::Log) -> anyhow::Result<DecodedAccountCreated> {
    use alloy::primitives::Log as PLog;
    // Convert RPC log to primitives Log and use typed decoder
    let prim = PLog::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
    let typed = AuthenticatorRegistry::AccountCreated::decode_log(&prim)?; // returns Log<AccountCreated>
    let ev = typed.data;

    let account_index_hex = format!("0x{:x}", ev.accountIndex);
    let recovery_address_bytes: Vec<u8> = ev.recoveryAddress.0.to_vec();
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
        ev.authenticator_addresses_hex.iter().map(|s| serde_json::Value::String(s.clone())).collect()
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

pub async fn stream_logs(ws_url: &str, pool: &PgPool, registry: Address, start_from: u64) -> anyhow::Result<()> {
    use futures_util::StreamExt;
    let ws = WsConnect::new(ws_url);
    let provider = ProviderBuilder::new().connect_ws(ws).await?;
    let filter = Filter::new()
        .address(registry)
        .event_signature(AuthenticatorRegistry::AccountCreated::SIGNATURE_HASH)
        .from_block(start_from);
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();
    while let Some(log) = stream.next().await {
        if let Ok(decoded) = decode_account_created(&log) {
            insert_account(pool, &decoded).await?;
            if let Some(bn) = log.block_number { save_checkpoint(pool, bn).await?; }
        }
    }
    Ok(())
}


