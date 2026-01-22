use std::{fmt, str::FromStr};

use alloy::primitives::{Address, U256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions, types::Json};

/// Type of commitment update event stored in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    AccountCreated,
    AccountUpdated,
    AccountRecovered,
    AuthenticationInserted,
    AuthenticationRemoved,
}

impl EventType {}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::AccountCreated => write!(f, "account_created"),
            EventType::AccountUpdated => write!(f, "account_updated"),
            EventType::AccountRecovered => write!(f, "account_recovered"),
            EventType::AuthenticationInserted => write!(f, "authentication_inserted"),
            EventType::AuthenticationRemoved => write!(f, "authentication_removed"),
        }
    }
}

impl FromStr for EventType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "account_created" => Ok(EventType::AccountCreated),
            "account_updated" => Ok(EventType::AccountUpdated),
            "account_recovered" => Ok(EventType::AccountRecovered),
            "authentication_inserted" => Ok(EventType::AuthenticationInserted),
            "authentication_removed" => Ok(EventType::AuthenticationRemoved),
            _ => Err(anyhow::anyhow!("Unknown event type: {}", s)),
        }
    }
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
    tracing::info!("Running migrations...");
    sqlx::migrate!("./migrations").run(pool).await?;
    tracing::info!("🟢 Migrations synced successfully.");
    Ok(())
}

pub async fn get_latest_block(pool: &PgPool) -> anyhow::Result<Option<u64>> {
    let rec: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT MAX(block_number) FROM world_id_events")
            .fetch_optional(pool)
            .await?;
    Ok(rec.and_then(|t| t.0.map(|v| v as u64)))
}

pub async fn insert_account(
    pool: &PgPool,
    leaf_index: &U256,
    recovery_address: &Address,
    authenticator_addresses: &[Address],
    authenticator_pubkeys: &[U256],
    offchain_signer_commitment: &U256,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"insert into accounts
        (leaf_index, recovery_address, authenticator_addresses, authenticator_pubkeys, offchain_signer_commitment)
        values ($1, $2, $3, $4, $5)
        on conflict (leaf_index) do nothing"#,
    )
        .bind(leaf_index.to_string())
        .bind(recovery_address.to_string())
        .bind(Json(
            authenticator_addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>(),
        ))
        .bind(Json(
            authenticator_pubkeys
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
        ))
        .bind(offchain_signer_commitment.to_string())
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
    event_type: EventType,
    new_commitment: U256,
    block_number: u64,
    tx_hash: &str,
    log_index: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"insert into world_id_events
        (leaf_index, event_type, new_commitment, block_number, tx_hash, log_index)
        values ($1, $2, $3, $4, $5, $6)
        on conflict (tx_hash, log_index) do nothing"#,
    )
    .bind(leaf_index.to_string())
    .bind(event_type.to_string())
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

    // Query world_id_events for recent changes
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (leaf_index)
            leaf_index,
            new_commitment
        FROM world_id_events
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

// =============================================================================
// Tree-related DB queries (extracted from tree module)
// =============================================================================

/// Fetch a batch of leaves from the accounts table using cursor-based pagination.
pub async fn fetch_leaves_batch(
    pool: &PgPool,
    last_cursor: &str,
    batch_size: i64,
) -> anyhow::Result<Vec<(String, String)>> {
    let rows = sqlx::query(
        "SELECT leaf_index, offchain_signer_commitment
         FROM accounts
         WHERE leaf_index > $1
         ORDER BY leaf_index ASC
         LIMIT $2",
    )
    .bind(last_cursor)
    .bind(batch_size)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(|row| {
            let leaf_index: String = row.try_get("leaf_index")?;
            let commitment: String = row.try_get("offchain_signer_commitment")?;
            Ok((leaf_index, commitment))
        })
        .collect()
}

/// Get the maximum block number from world_id_events.
pub async fn get_max_event_block(pool: &PgPool) -> anyhow::Result<u64> {
    let result = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COALESCE(MAX(block_number), 0) FROM world_id_events",
    )
    .fetch_one(pool)
    .await?
    .unwrap_or(0);

    Ok(result as u64)
}

/// Get the maximum event ID from world_id_events.
/// This is the primary key that auto-increments with each insertion.
pub async fn get_max_event_id(pool: &PgPool) -> anyhow::Result<i64> {
    let result =
        sqlx::query_scalar::<_, Option<i64>>("SELECT COALESCE(MAX(id), 0) FROM world_id_events")
            .fetch_one(pool)
            .await?
            .unwrap_or(0);

    Ok(result)
}

/// Count active (non-zero) leaves in the accounts table.
pub async fn get_active_leaf_count(pool: &PgPool) -> anyhow::Result<u64> {
    let result =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts WHERE leaf_index != '0'")
            .fetch_one(pool)
            .await?;

    Ok(result as u64)
}

/// Count total events in world_id_events.
pub async fn get_total_event_count(pool: &PgPool) -> anyhow::Result<u64> {
    let result = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM world_id_events")
        .fetch_one(pool)
        .await?;

    Ok(result as u64)
}

/// Raw event row for replay operations.
#[derive(Debug)]
pub struct CommitmentEventRow {
    pub id: i64,
    pub leaf_index: String,
    pub new_commitment: String,
    pub block_number: i64,
}

/// Fetch events for replay using event ID-based pagination.
/// Returns events where id > from_event_id, ordered by ID (insertion order).
/// This ensures all events are replayed regardless of block_number,
/// which is critical for handling blockchain reorgs where events with older
/// block numbers may be inserted after events with newer block numbers.
pub async fn fetch_events_for_replay(
    pool: &PgPool,
    from_event_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<CommitmentEventRow>> {
    let rows = sqlx::query(
        "SELECT id, leaf_index, event_type, new_commitment, block_number
         FROM world_id_events
         WHERE id > $1
         ORDER BY id ASC
         LIMIT $2",
    )
    .bind(from_event_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        events.push(CommitmentEventRow {
            id: row.try_get("id")?,
            leaf_index: row.try_get("leaf_index")?,
            new_commitment: row.try_get("new_commitment")?,
            block_number: row.try_get("block_number")?,
        });
    }

    Ok(events)
}
