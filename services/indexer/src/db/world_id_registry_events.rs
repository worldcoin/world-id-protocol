use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, postgres::PgRow};
use tracing::instrument;

use crate::{
    blockchain::{
        AccountCreatedEvent, AccountRecoveredEvent, AccountUpdatedEvent,
        AuthenticatorInsertedEvent, AuthenticatorRemovedEvent, BlockchainEvent, RegistryEvent,
        RootRecordedEvent,
    },
    db::{DBError, DBResult},
    invalid_field, missing_field,
};

/// Event identifier for World ID Registry events
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct WorldIdRegistryEventId {
    pub block_number: u64,
    pub log_index: u64,
}

impl From<(u64, u64)> for WorldIdRegistryEventId {
    fn from(value: (u64, u64)) -> Self {
        WorldIdRegistryEventId {
            block_number: value.0,
            log_index: value.1,
        }
    }
}

/// Full World ID Registry event stored in database
#[derive(Debug, Clone, PartialEq)]
pub struct WorldIdRegistryEvent {
    pub id: WorldIdRegistryEventId,
    pub block_hash: U256,
    pub tx_hash: U256,
    pub event_type: WorldIdRegistryEventType,
    pub leaf_index: Option<u64>,
    pub event_data: serde_json::Value,
}

/// Type of registry event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldIdRegistryEventType {
    AccountCreated,
    AccountUpdated,
    AuthenticatorInserted,
    AuthenticatorRemoved,
    AccountRecovered,
    RootRecorded,
}

impl std::fmt::Display for WorldIdRegistryEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorldIdRegistryEventType::AccountCreated => write!(f, "account_created"),
            WorldIdRegistryEventType::AccountUpdated => write!(f, "account_updated"),
            WorldIdRegistryEventType::AuthenticatorInserted => {
                write!(f, "authenticator_inserted")
            }
            WorldIdRegistryEventType::AuthenticatorRemoved => write!(f, "authenticator_removed"),
            WorldIdRegistryEventType::AccountRecovered => write!(f, "account_recovered"),
            WorldIdRegistryEventType::RootRecorded => write!(f, "root_recorded"),
        }
    }
}

impl<'a> TryFrom<&'a str> for WorldIdRegistryEventType {
    type Error = crate::db::DBError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "account_created" => Ok(WorldIdRegistryEventType::AccountCreated),
            "account_updated" => Ok(WorldIdRegistryEventType::AccountUpdated),
            "authenticator_inserted" => Ok(WorldIdRegistryEventType::AuthenticatorInserted),
            "authenticator_removed" => Ok(WorldIdRegistryEventType::AuthenticatorRemoved),
            "account_recovered" => Ok(WorldIdRegistryEventType::AccountRecovered),
            "root_recorded" => Ok(WorldIdRegistryEventType::RootRecorded),
            _ => Err(DBError::UnknownEventType(value.to_string())),
        }
    }
}

/// Serialize event data to JSON for storage
pub fn serialize_event_data(event: &RegistryEvent) -> serde_json::Value {
    match event {
        RegistryEvent::AccountCreated(ev) => serde_json::json!({
            "recovery_address": format!("{:?}", ev.recovery_address),
            "authenticator_addresses": ev.authenticator_addresses.iter()
                .map(|a| format!("{:?}", a))
                .collect::<Vec<_>>(),
            "authenticator_pubkeys": ev.authenticator_pubkeys.iter()
                .map(|p| format!("{:#x}", p))
                .collect::<Vec<_>>(),
            "offchain_signer_commitment": format!("{:#x}", ev.offchain_signer_commitment),
        }),
        RegistryEvent::AccountUpdated(ev) => serde_json::json!({
            "pubkey_id": ev.pubkey_id,
            "new_authenticator_pubkey": format!("{:#x}", ev.new_authenticator_pubkey),
            "old_authenticator_address": format!("{:?}", ev.old_authenticator_address),
            "new_authenticator_address": format!("{:?}", ev.new_authenticator_address),
            "old_offchain_signer_commitment": format!("{:#x}", ev.old_offchain_signer_commitment),
            "new_offchain_signer_commitment": format!("{:#x}", ev.new_offchain_signer_commitment),
        }),
        RegistryEvent::AuthenticatorInserted(ev) => serde_json::json!({
            "pubkey_id": ev.pubkey_id,
            "authenticator_address": format!("{:?}", ev.authenticator_address),
            "new_authenticator_pubkey": format!("{:#x}", ev.new_authenticator_pubkey),
            "old_offchain_signer_commitment": format!("{:#x}", ev.old_offchain_signer_commitment),
            "new_offchain_signer_commitment": format!("{:#x}", ev.new_offchain_signer_commitment),
        }),
        RegistryEvent::AuthenticatorRemoved(ev) => serde_json::json!({
            "pubkey_id": ev.pubkey_id,
            "authenticator_address": format!("{:?}", ev.authenticator_address),
            "authenticator_pubkey": format!("{:#x}", ev.authenticator_pubkey),
            "old_offchain_signer_commitment": format!("{:#x}", ev.old_offchain_signer_commitment),
            "new_offchain_signer_commitment": format!("{:#x}", ev.new_offchain_signer_commitment),
        }),
        RegistryEvent::AccountRecovered(ev) => serde_json::json!({
            "new_authenticator_address": format!("{:?}", ev.new_authenticator_address),
            "new_authenticator_pubkey": format!("{:#x}", ev.new_authenticator_pubkey),
            "old_offchain_signer_commitment": format!("{:#x}", ev.old_offchain_signer_commitment),
            "new_offchain_signer_commitment": format!("{:#x}", ev.new_offchain_signer_commitment),
        }),
        RegistryEvent::RootRecorded(ev) => serde_json::json!({
            "root": format!("{:#x}", ev.root),
            "timestamp": format!("{}", ev.timestamp),
        }),
    }
}

/// Deserialize event data from JSON back to RootRecordedEvent
pub fn deserialize_root_recorded(event_data: &serde_json::Value) -> DBResult<RootRecordedEvent> {
    let root = event_data["root"]
        .as_str()
        .ok_or_else(|| missing_field!("root"))?
        .parse()
        .map_err(|_| invalid_field!("root", "failed to parse U256"))?;

    let timestamp = event_data["timestamp"]
        .as_str()
        .ok_or_else(|| missing_field!("timestamp"))?
        .parse()
        .map_err(|_| invalid_field!("timestamp", "failed to parse U256"))?;

    Ok(RootRecordedEvent { root, timestamp })
}

/// Deserialize event data from JSON back to RegistryEvent
pub fn deserialize_registry_event(
    event_type: WorldIdRegistryEventType,
    leaf_index: Option<u64>,
    event_data: &serde_json::Value,
) -> DBResult<RegistryEvent> {
    match event_type {
        WorldIdRegistryEventType::AccountCreated => {
            let recovery_address = event_data["recovery_address"]
                .as_str()
                .ok_or_else(|| missing_field!("recovery_address"))?
                .parse()
                .map_err(|_| invalid_field!("recovery_address", "failed to parse address"))?;

            let authenticator_addresses: Vec<_> = event_data["authenticator_addresses"]
                .as_array()
                .ok_or_else(|| missing_field!("authenticator_addresses"))?
                .iter()
                .filter_map(|v| v.as_str()?.parse().ok())
                .collect();

            let authenticator_pubkeys: Vec<_> = event_data["authenticator_pubkeys"]
                .as_array()
                .ok_or_else(|| missing_field!("authenticator_pubkeys"))?
                .iter()
                .filter_map(|v| v.as_str()?.parse().ok())
                .collect();

            let offchain_signer_commitment = event_data["offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("offchain_signer_commitment", "failed to parse U256")
                })?;

            Ok(RegistryEvent::AccountCreated(AccountCreatedEvent {
                leaf_index: leaf_index.ok_or_else(|| missing_field!("leaf_index"))?,
                recovery_address,
                authenticator_addresses,
                authenticator_pubkeys,
                offchain_signer_commitment,
            }))
        }
        WorldIdRegistryEventType::AccountUpdated => {
            let pubkey_id = event_data["pubkey_id"]
                .as_u64()
                .ok_or_else(|| missing_field!("pubkey_id"))? as u32;

            let new_authenticator_pubkey = event_data["new_authenticator_pubkey"]
                .as_str()
                .ok_or_else(|| missing_field!("new_authenticator_pubkey"))?
                .parse()
                .map_err(|_| invalid_field!("new_authenticator_pubkey", "failed to parse U256"))?;

            let old_authenticator_address = event_data["old_authenticator_address"]
                .as_str()
                .ok_or_else(|| missing_field!("old_authenticator_address"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("old_authenticator_address", "failed to parse address")
                })?;

            let new_authenticator_address = event_data["new_authenticator_address"]
                .as_str()
                .ok_or_else(|| missing_field!("new_authenticator_address"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("new_authenticator_address", "failed to parse address")
                })?;

            let old_offchain_signer_commitment = event_data["old_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("old_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("old_offchain_signer_commitment", "failed to parse U256")
                })?;

            let new_offchain_signer_commitment = event_data["new_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("new_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("new_offchain_signer_commitment", "failed to parse U256")
                })?;

            Ok(RegistryEvent::AccountUpdated(AccountUpdatedEvent {
                leaf_index: leaf_index.ok_or_else(|| missing_field!("leaf_index"))?,
                pubkey_id,
                new_authenticator_pubkey,
                old_authenticator_address,
                new_authenticator_address,
                old_offchain_signer_commitment,
                new_offchain_signer_commitment,
            }))
        }
        WorldIdRegistryEventType::AuthenticatorInserted => {
            let pubkey_id = event_data["pubkey_id"]
                .as_u64()
                .ok_or_else(|| missing_field!("pubkey_id"))? as u32;

            let authenticator_address = event_data["authenticator_address"]
                .as_str()
                .ok_or_else(|| missing_field!("authenticator_address"))?
                .parse()
                .map_err(|_| invalid_field!("authenticator_address", "failed to parse address"))?;

            let new_authenticator_pubkey = event_data["new_authenticator_pubkey"]
                .as_str()
                .ok_or_else(|| missing_field!("new_authenticator_pubkey"))?
                .parse()
                .map_err(|_| invalid_field!("new_authenticator_pubkey", "failed to parse U256"))?;

            let old_offchain_signer_commitment = event_data["old_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("old_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("old_offchain_signer_commitment", "failed to parse U256")
                })?;

            let new_offchain_signer_commitment = event_data["new_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("new_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("new_offchain_signer_commitment", "failed to parse U256")
                })?;

            Ok(RegistryEvent::AuthenticatorInserted(
                AuthenticatorInsertedEvent {
                    leaf_index: leaf_index.ok_or_else(|| missing_field!("leaf_index"))?,
                    pubkey_id,
                    authenticator_address,
                    new_authenticator_pubkey,
                    old_offchain_signer_commitment,
                    new_offchain_signer_commitment,
                },
            ))
        }
        WorldIdRegistryEventType::AuthenticatorRemoved => {
            let pubkey_id = event_data["pubkey_id"]
                .as_u64()
                .ok_or_else(|| missing_field!("pubkey_id"))? as u32;

            let authenticator_address = event_data["authenticator_address"]
                .as_str()
                .ok_or_else(|| missing_field!("authenticator_address"))?
                .parse()
                .map_err(|_| invalid_field!("authenticator_address", "failed to parse address"))?;

            let authenticator_pubkey = event_data["authenticator_pubkey"]
                .as_str()
                .ok_or_else(|| missing_field!("authenticator_pubkey"))?
                .parse()
                .map_err(|_| invalid_field!("authenticator_pubkey", "failed to parse U256"))?;

            let old_offchain_signer_commitment = event_data["old_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("old_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("old_offchain_signer_commitment", "failed to parse U256")
                })?;

            let new_offchain_signer_commitment = event_data["new_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("new_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("new_offchain_signer_commitment", "failed to parse U256")
                })?;

            Ok(RegistryEvent::AuthenticatorRemoved(
                AuthenticatorRemovedEvent {
                    leaf_index: leaf_index.ok_or_else(|| missing_field!("leaf_index"))?,
                    pubkey_id,
                    authenticator_address,
                    authenticator_pubkey,
                    old_offchain_signer_commitment,
                    new_offchain_signer_commitment,
                },
            ))
        }
        WorldIdRegistryEventType::AccountRecovered => {
            let new_authenticator_address = event_data["new_authenticator_address"]
                .as_str()
                .ok_or_else(|| missing_field!("new_authenticator_address"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("new_authenticator_address", "failed to parse address")
                })?;

            let new_authenticator_pubkey = event_data["new_authenticator_pubkey"]
                .as_str()
                .ok_or_else(|| missing_field!("new_authenticator_pubkey"))?
                .parse()
                .map_err(|_| invalid_field!("new_authenticator_pubkey", "failed to parse U256"))?;

            let old_offchain_signer_commitment = event_data["old_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("old_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("old_offchain_signer_commitment", "failed to parse U256")
                })?;

            let new_offchain_signer_commitment = event_data["new_offchain_signer_commitment"]
                .as_str()
                .ok_or_else(|| missing_field!("new_offchain_signer_commitment"))?
                .parse()
                .map_err(|_| {
                    invalid_field!("new_offchain_signer_commitment", "failed to parse U256")
                })?;

            Ok(RegistryEvent::AccountRecovered(AccountRecoveredEvent {
                leaf_index: leaf_index.ok_or_else(|| missing_field!("leaf_index"))?,
                new_authenticator_address,
                new_authenticator_pubkey,
                old_offchain_signer_commitment,
                new_offchain_signer_commitment,
            }))
        }
        WorldIdRegistryEventType::RootRecorded => {
            let root = event_data["root"]
                .as_str()
                .ok_or_else(|| missing_field!("root"))?
                .parse()
                .map_err(|_| invalid_field!("root", "failed to parse U256"))?;

            let timestamp = event_data["timestamp"]
                .as_str()
                .ok_or_else(|| missing_field!("timestamp"))?
                .parse()
                .map_err(|_| invalid_field!("timestamp", "failed to parse U256"))?;

            Ok(RegistryEvent::RootRecorded(RootRecordedEvent {
                root,
                timestamp,
            }))
        }
    }
}

/// A block number with all distinct block hashes observed for it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockWithConflictingHashes {
    pub block_number: u64,
    pub block_hashes: Vec<U256>,
}

pub struct WorldIdRegistryEvents<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> WorldIdRegistryEvents<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            _marker: std::marker::PhantomData,
        }
    }

    /// Insert a full registry event
    #[instrument(level = "info", skip(self, event))]
    pub async fn insert_event(self, event: &BlockchainEvent<RegistryEvent>) -> DBResult<()> {
        let event_type = match &event.details {
            RegistryEvent::AccountCreated(_) => WorldIdRegistryEventType::AccountCreated,
            RegistryEvent::AccountUpdated(_) => WorldIdRegistryEventType::AccountUpdated,
            RegistryEvent::AuthenticatorInserted(_) => {
                WorldIdRegistryEventType::AuthenticatorInserted
            }
            RegistryEvent::AuthenticatorRemoved(_) => {
                WorldIdRegistryEventType::AuthenticatorRemoved
            }
            RegistryEvent::AccountRecovered(_) => WorldIdRegistryEventType::AccountRecovered,
            RegistryEvent::RootRecorded(_) => WorldIdRegistryEventType::RootRecorded,
        };

        let leaf_index = match &event.details {
            RegistryEvent::AccountCreated(ev) => Some(ev.leaf_index as i64),
            RegistryEvent::AccountUpdated(ev) => Some(ev.leaf_index as i64),
            RegistryEvent::AuthenticatorInserted(ev) => Some(ev.leaf_index as i64),
            RegistryEvent::AuthenticatorRemoved(ev) => Some(ev.leaf_index as i64),
            RegistryEvent::AccountRecovered(ev) => Some(ev.leaf_index as i64),
            RegistryEvent::RootRecorded(_) => None,
        };

        let event_data = serialize_event_data(&event.details);

        sqlx::query(
            r#"
                INSERT INTO world_id_registry_events (
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (block_number, log_index) DO NOTHING
            "#,
        )
        .bind(event.block_number as i64)
        .bind(event.log_index as i64)
        .bind(event.block_hash)
        .bind(event.tx_hash)
        .bind(event_type.to_string())
        .bind(leaf_index)
        .bind(event_data)
        .execute(self.executor)
        .await?;

        Ok(())
    }

    /// Get an event by its ID
    #[instrument(level = "info", skip(self, event_id))]
    pub async fn get_event<T: Into<WorldIdRegistryEventId>>(
        self,
        event_id: T,
    ) -> DBResult<Option<WorldIdRegistryEvent>> {
        let event_id = event_id.into();
        let result = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                FROM world_id_registry_events
                WHERE
                    block_number = $1 AND log_index = $2
            "#,
        )
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_event(&row)).transpose()
    }

    /// Get all events for a specific leaf index up to (and including) the given event_id
    #[instrument(level = "info", skip(self))]
    pub async fn get_events_for_leaf(
        self,
        leaf_index: u64,
        event_id: &WorldIdRegistryEventId,
    ) -> DBResult<Vec<BlockchainEvent<RegistryEvent>>> {
        let rows = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                FROM world_id_registry_events
                WHERE
                    leaf_index = $1
                    AND (
                        (block_number < $2)
                        OR (block_number = $2 AND log_index <= $3)
                    )
                ORDER BY
                    block_number ASC,
                    log_index ASC
            "#,
        )
        .bind(leaf_index as i64)
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter()
            .map(|row| Self::map_event_to_blockchain_event(row))
            .collect()
    }

    /// Delete events after the given event_id
    #[instrument(level = "info", skip(self))]
    pub async fn delete_after_event(self, event_id: &WorldIdRegistryEventId) -> DBResult<u64> {
        let result = sqlx::query(
            r#"
                DELETE FROM world_id_registry_events
                WHERE (block_number > $1)
                   OR (block_number = $1 AND log_index > $2)
            "#,
        )
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .execute(self.executor)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete all events with block_number >= the given block_number
    #[instrument(level = "info", skip(self))]
    pub async fn delete_from_block_number_inclusively(self, block_number: u64) -> DBResult<u64> {
        let result = sqlx::query(
            r#"
                DELETE FROM world_id_registry_events
                WHERE block_number >= $1
            "#,
        )
        .bind(block_number as i64)
        .execute(self.executor)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get the latest block number from the registry events
    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_block(self) -> DBResult<Option<u64>> {
        let rec: Option<(Option<i64>,)> =
            sqlx::query_as("SELECT MAX(block_number) FROM world_id_registry_events")
                .fetch_optional(self.executor)
                .await?;
        Ok(rec.and_then(|t| t.0.map(|v| v as u64)))
    }

    /// Get all unique block hashes for events at the specified block number
    #[instrument(level = "info", skip(self))]
    pub async fn get_block_hashes(self, block_number: u64) -> DBResult<Vec<U256>> {
        let rows = sqlx::query(
            r#"
                SELECT DISTINCT block_hash
                FROM world_id_registry_events
                WHERE block_number = $1
                ORDER BY block_hash
            "#,
        )
        .bind(block_number as i64)
        .fetch_all(self.executor)
        .await?;

        Ok(rows
            .iter()
            .map(|row| row.get::<U256, _>("block_hash"))
            .collect())
    }

    /// Get the latest event ID from the registry events
    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_id(self) -> DBResult<Option<WorldIdRegistryEventId>> {
        let result = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index
                FROM world_id_registry_events
                ORDER BY
                    block_number DESC,
                    log_index DESC
                LIMIT 1
            "#,
        )
        .fetch_optional(self.executor)
        .await?;

        if let Some(row) = result {
            Ok(Some(WorldIdRegistryEventId {
                block_number: row.get::<i64, _>("block_number") as u64,
                log_index: row.get::<i64, _>("log_index") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get the latest event ID from the registry events for given block number
    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_id_for_block_number(
        self,
        block_number: u64,
    ) -> DBResult<Option<WorldIdRegistryEventId>> {
        let result = sqlx::query(
            r#"
                    SELECT
                        block_number,
                        log_index
                    FROM world_id_registry_events
                    WHERE
                        block_number = $1
                    ORDER BY
                        log_index DESC
                    LIMIT 1
                "#,
        )
        .bind(block_number as i64)
        .fetch_optional(self.executor)
        .await?;

        if let Some(row) = result {
            Ok(Some(WorldIdRegistryEventId {
                block_number: row.get::<i64, _>("block_number") as u64,
                log_index: row.get::<i64, _>("log_index") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get events after the given event_id (for tree syncing)
    #[instrument(level = "info", skip(self))]
    pub async fn get_after(
        self,
        event_id: WorldIdRegistryEventId,
        limit: u64,
    ) -> DBResult<Vec<BlockchainEvent<RegistryEvent>>> {
        let rows = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                FROM world_id_registry_events
                WHERE
                    (block_number = $1 AND log_index > $2)
                    OR block_number > $1
                ORDER BY
                    block_number ASC,
                    log_index ASC
                LIMIT $3
            "#,
        )
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .bind(limit as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter()
            .map(|row| Self::map_event_to_blockchain_event(row))
            .collect()
    }

    /// Check if a root exists in the database (searches RootRecorded events)
    #[instrument(level = "info", skip(self))]
    pub async fn root_exists(self, root: &alloy::primitives::U256) -> DBResult<bool> {
        let root_hex = format!("{:#x}", root);

        let result = sqlx::query(
            r#"
                SELECT 1
                FROM world_id_registry_events
                WHERE event_type = 'root_recorded'
                  AND event_data->>'root' = $1
                LIMIT 1
            "#,
        )
        .bind(&root_hex)
        .fetch_optional(self.executor)
        .await?;

        Ok(result.is_some())
    }

    /// Get the latest RootRecorded event
    #[instrument(level = "info", skip(self))]
    pub async fn get_latest_root_recorded(
        self,
    ) -> DBResult<Option<BlockchainEvent<RootRecordedEvent>>> {
        let row = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                FROM world_id_registry_events
                WHERE event_type = 'root_recorded'
                ORDER BY
                    block_number DESC,
                    log_index DESC
                LIMIT 1
            "#,
        )
        .fetch_optional(self.executor)
        .await?;

        if let Some(row) = row {
            Ok(Some(Self::map_root_recorded_event(&row)?))
        } else {
            Ok(None)
        }
    }

    /// Get the all RootRecorded events after (inclusively) the provided block number
    #[instrument(level = "info", skip(self))]
    pub async fn get_roots_recorded_after_block_number_inclusively(
        self,
        block_number: u64,
    ) -> DBResult<Vec<BlockchainEvent<RootRecordedEvent>>> {
        let rows = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                FROM world_id_registry_events
                WHERE event_type = 'root_recorded'
                  AND (
                    block_number >= $1
                  )
                ORDER BY
                    block_number ASC,
                    log_index ASC
                LIMIT 1
            "#,
        )
        .bind(block_number as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter()
            .map(|row| Self::map_root_recorded_event(row))
            .collect()
    }

    /// Get a batch of RootRecorded events in reverse chronological order, starting
    /// strictly before `before` (exclusive). Returns at most `limit` events.
    #[instrument(level = "info", skip(self))]
    pub async fn get_root_recorded_events_desc_before(
        self,
        before: WorldIdRegistryEventId,
        limit: u64,
    ) -> DBResult<Vec<BlockchainEvent<RootRecordedEvent>>> {
        let rows = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                FROM world_id_registry_events
                WHERE event_type = 'root_recorded'
                  AND (
                      block_number < $1
                      OR (block_number = $1 AND log_index < $2)
                  )
                ORDER BY
                    block_number DESC,
                    log_index DESC
                LIMIT $3
            "#,
        )
        .bind(before.block_number as i64)
        .bind(before.log_index as i64)
        .bind(limit as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter()
            .map(|row| Self::map_root_recorded_event(row))
            .collect()
    }

    /// Get the latest RootRecorded event strictly before the given event_id
    #[instrument(level = "info", skip(self))]
    pub async fn get_root_recorded_before(
        self,
        event_id: WorldIdRegistryEventId,
    ) -> DBResult<Option<BlockchainEvent<RootRecordedEvent>>> {
        let row = sqlx::query(
            r#"
                SELECT
                    block_number,
                    log_index,
                    block_hash,
                    tx_hash,
                    event_type,
                    leaf_index,
                    event_data
                FROM world_id_registry_events
                WHERE event_type = 'root_recorded'
                  AND (
                      block_number < $1
                      OR (block_number = $1 AND log_index < $2)
                  )
                ORDER BY
                    block_number DESC,
                    log_index DESC
                LIMIT 1
            "#,
        )
        .bind(event_id.block_number as i64)
        .bind(event_id.log_index as i64)
        .fetch_optional(self.executor)
        .await?;

        if let Some(row) = row {
            Ok(Some(Self::map_root_recorded_event(&row)?))
        } else {
            Ok(None)
        }
    }

    /// Get block numbers that have more than one distinct block_hash, along with those hashes
    #[instrument(level = "info", skip(self))]
    pub async fn get_blocks_with_conflicting_hashes(
        self,
    ) -> DBResult<Vec<BlockWithConflictingHashes>> {
        let rows = sqlx::query(
            r#"
                SELECT block_number, block_hash
                FROM world_id_registry_events
                WHERE block_number IN (
                    SELECT block_number
                    FROM world_id_registry_events
                    GROUP BY block_number
                    HAVING COUNT(DISTINCT block_hash) > 1
                )
                GROUP BY block_number, block_hash
                ORDER BY block_number ASC
            "#,
        )
        .fetch_all(self.executor)
        .await?;

        let mut result: Vec<BlockWithConflictingHashes> = Vec::new();
        for row in &rows {
            let block_number = row.get::<i64, _>("block_number") as u64;
            let block_hash = row.get::<U256, _>("block_hash");
            if let Some(entry) = result.last_mut().filter(|e| e.block_number == block_number) {
                entry.block_hashes.push(block_hash);
            } else {
                result.push(BlockWithConflictingHashes {
                    block_number,
                    block_hashes: vec![block_hash],
                });
            }
        }

        Ok(result)
    }

    fn map_event(row: &PgRow) -> DBResult<WorldIdRegistryEvent> {
        let event_id = WorldIdRegistryEventId {
            block_number: row.get::<i64, _>("block_number") as u64,
            log_index: row.get::<i64, _>("log_index") as u64,
        };

        let event_type = WorldIdRegistryEventType::try_from(row.get::<&str, _>("event_type"))?;

        Ok(WorldIdRegistryEvent {
            id: event_id,
            block_hash: row.get::<U256, _>("block_hash"),
            tx_hash: row.get::<U256, _>("tx_hash"),
            event_type,
            leaf_index: row.get::<Option<i64>, _>("leaf_index").map(|i| i as u64),
            event_data: row.get::<serde_json::Value, _>("event_data"),
        })
    }

    fn map_root_recorded_event(row: &PgRow) -> DBResult<BlockchainEvent<RootRecordedEvent>> {
        let event = Self::map_event(row)?;
        let details = deserialize_root_recorded(&event.event_data)?;
        Ok(BlockchainEvent {
            block_number: event.id.block_number,
            block_hash: event.block_hash,
            tx_hash: event.tx_hash,
            log_index: event.id.log_index,
            details,
        })
    }

    fn map_event_to_blockchain_event(row: &PgRow) -> DBResult<BlockchainEvent<RegistryEvent>> {
        let event = Self::map_event(row)?;

        let details =
            deserialize_registry_event(event.event_type, event.leaf_index, &event.event_data)?;

        Ok(BlockchainEvent {
            block_number: event.id.block_number,
            block_hash: event.block_hash,
            tx_hash: event.tx_hash,
            log_index: event.id.log_index,
            details,
        })
    }
}
