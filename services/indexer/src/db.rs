use crate::events::AccountCreatedEvent;
use alloy::primitives::{Address, U256};
use sqlx::{postgres::PgPoolOptions, types::Json, PgPool, Row};

pub async fn make_db_pool(db_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(db_url)
        .await?;
    Ok(pool)
}

pub async fn init_db(pool: &PgPool) -> anyhow::Result<()> {
    // Run sqlx migrations from ./migrations
    tracing::info!("Running migrations...");
    sqlx::migrate!("./migrations").run(pool).await?;
    tracing::info!("🟢 Migrations synced successfully.");
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

pub async fn insert_account(pool: &PgPool, ev: &AccountCreatedEvent) -> anyhow::Result<()> {
    sqlx::query(
        r#"insert into accounts
        (leaf_index, recovery_address, authenticator_addresses, authenticator_pubkeys, offchain_signer_commitment)
        values ($1, $2, $3, $4, $5)
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
) -> anyhow::Result<()> {
    // Update authenticator at specific index (pubkey_id)
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), false),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), false),
            offchain_signer_commitment = $5
        where leaf_index = $1"#,
    )
        .bind(leaf_index.to_string())
        .bind(format!("{{{pubkey_id}}}")) // JSONB path format: {0}, {1}, etc
        .bind(new_address.to_string())
        .bind(new_pubkey.to_string())
        .bind(new_commitment.to_string())
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
) -> anyhow::Result<()> {
    // Ensure arrays are large enough and insert at specific index
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), true),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), true),
            offchain_signer_commitment = $5
        where leaf_index = $1"#,
    )
        .bind(leaf_index.to_string())
        .bind(format!("{{{pubkey_id}}}"))
        .bind(new_address.to_string())
        .bind(new_pubkey.to_string())
        .bind(new_commitment.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_authenticator_at_index(
    pool: &PgPool,
    leaf_index: U256,
    pubkey_id: u32,
    new_commitment: U256,
) -> anyhow::Result<()> {
    // Remove authenticator at specific index by setting to null
    sqlx::query(
        r#"update accounts
        set authenticator_addresses = jsonb_set(authenticator_addresses, $2, 'null'::jsonb, false),
            authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, 'null'::jsonb, false),
            offchain_signer_commitment = $3
        where leaf_index = $1"#,
    )
    .bind(leaf_index.to_string())
    .bind(format!("{{{pubkey_id}}}"))
    .bind(new_commitment.to_string())
    .execute(pool)
    .await?;
    Ok(())
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

pub async fn fetch_recent_account_updates(
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
