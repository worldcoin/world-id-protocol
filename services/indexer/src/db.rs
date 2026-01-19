use std::fmt;
use std::str::FromStr;

use crate::events::AccountCreatedEvent;
use alloy::primitives::{Address, U256};
use sqlx::{postgres::PgPoolOptions, types::Json, PgPool, Row};

/// Type of commitment update event stored in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Created,
    Updated,
    Inserted,
    Removed,
    Recovered,
}

impl EventType {
    /// Returns true if this event type sets a non-zero commitment value.
    #[must_use]
    pub fn sets_value(&self) -> bool {
        !matches!(self, EventType::Removed)
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::Created => write!(f, "created"),
            EventType::Updated => write!(f, "updated"),
            EventType::Inserted => write!(f, "inserted"),
            EventType::Removed => write!(f, "removed"),
            EventType::Recovered => write!(f, "recovered"),
        }
    }
}

impl FromStr for EventType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "created" => Ok(EventType::Created),
            "updated" => Ok(EventType::Updated),
            "inserted" => Ok(EventType::Inserted),
            "removed" => Ok(EventType::Removed),
            "recovered" => Ok(EventType::Recovered),
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
    event_type: EventType,
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

// =============================================================================
// Tree-related DB queries (extracted from tree module)
// =============================================================================

/// Fetch all account leaves for tree building.
/// Returns raw strings to let the caller handle parsing and tree-specific logic.
pub async fn fetch_all_leaves(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    let rows = sqlx::query(
        "SELECT leaf_index, offchain_signer_commitment FROM accounts ORDER BY leaf_index ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut leaves = Vec::with_capacity(rows.len());
    for row in rows {
        let leaf_index: String = row.try_get("leaf_index")?;
        let commitment: String = row.try_get("offchain_signer_commitment")?;
        leaves.push((leaf_index, commitment));
    }

    Ok(leaves)
}

/// Get the maximum block number from commitment_update_events.
pub async fn get_max_event_block(pool: &PgPool) -> anyhow::Result<u64> {
    let result = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COALESCE(MAX(block_number), 0) FROM commitment_update_events",
    )
    .fetch_one(pool)
    .await?
    .unwrap_or(0);

    Ok(result as u64)
}

/// Count active (non-zero) leaves in the accounts table.
pub async fn get_active_leaf_count(pool: &PgPool) -> anyhow::Result<u64> {
    let result =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts WHERE leaf_index != '0'")
            .fetch_one(pool)
            .await?;

    Ok(result as u64)
}

/// Get the last event ID up to (and including) a specific block number.
pub async fn get_last_event_id_up_to_block(
    pool: &PgPool,
    block_number: u64,
) -> anyhow::Result<i64> {
    let result = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(id) FROM commitment_update_events WHERE block_number <= $1",
    )
    .bind(block_number as i64)
    .fetch_one(pool)
    .await?
    .unwrap_or(0);

    Ok(result)
}

/// Count total events in commitment_update_events.
pub async fn get_total_event_count(pool: &PgPool) -> anyhow::Result<u64> {
    let result = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM commitment_update_events")
        .fetch_one(pool)
        .await?;

    Ok(result as u64)
}

/// Raw event row for replay operations.
#[derive(Debug)]
pub struct CommitmentEventRow {
    pub leaf_index: String,
    pub event_type: EventType,
    pub new_commitment: String,
    pub block_number: i64,
    pub log_index: i64,
}

/// Fetch events for replay using keyset pagination.
/// Returns events where (block_number > from_block) OR (block_number = from_block AND log_index > from_log_index).
pub async fn fetch_events_for_replay(
    pool: &PgPool,
    from_block: i64,
    from_log_index: i64,
    limit: i64,
) -> anyhow::Result<Vec<CommitmentEventRow>> {
    let rows = sqlx::query(
        "SELECT leaf_index, event_type, new_commitment, block_number, log_index
         FROM commitment_update_events
         WHERE (block_number > $1) OR (block_number = $1 AND log_index > $2)
         ORDER BY block_number ASC, log_index ASC
         LIMIT $3",
    )
    .bind(from_block)
    .bind(from_log_index)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let event_type_str: String = row.try_get("event_type")?;
        events.push(CommitmentEventRow {
            leaf_index: row.try_get("leaf_index")?,
            event_type: event_type_str.parse()?,
            new_commitment: row.try_get("new_commitment")?,
            block_number: row.try_get("block_number")?,
            log_index: row.try_get("log_index")?,
        });
    }

    Ok(events)
}
