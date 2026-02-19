use crate::db::DBResult;
use alloy::primitives::{Address, U160, U256};
use core::fmt;
use futures_util::{Stream, StreamExt as _};
use sqlx::{Postgres, Row, postgres::PgRow, types::Json};
use tracing::instrument;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountLatestEventId {
    pub latest_block_number: u64,
    pub latest_log_index: u64,
}

impl From<(u64, u64)> for AccountLatestEventId {
    fn from(value: (u64, u64)) -> Self {
        AccountLatestEventId {
            latest_block_number: value.0,
            latest_log_index: value.1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub leaf_index: u64,
    pub recovery_address: Address,
    pub authenticator_addresses: Vec<Option<Address>>,
    pub authenticator_pubkeys: Vec<Option<U256>>,
    pub offchain_signer_commitment: U256,
    pub latest_event_id: AccountLatestEventId,
}

pub struct Accounts<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> Accounts<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            _marker: std::marker::PhantomData,
        }
    }

    #[instrument(level = "info", skip(self))]
    pub fn stream_leaf_index_and_offchain_signer_commitment(
        self,
    ) -> impl Stream<Item = DBResult<(u64, U256)>> + 'a {
        sqlx::query(
            r#"
                SELECT
                    leaf_index,
                    offchain_signer_commitment
                FROM accounts
                ORDER BY
                    leaf_index ASC
            "#,
        )
        .fetch(self.executor)
        .map(|row_result| {
            let row = row_result?;
            let leaf_index = Self::map_leaf_index(&row)?;
            let commitment = Self::map_offchain_signer_commitment(&row)?;
            Ok((leaf_index, commitment))
        })
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_offchain_signer_commitment_and_authenticator_pubkeys_by_leaf_index(
        self,
        leaf_index: u64,
    ) -> DBResult<Option<(U256, Vec<Option<U256>>)>> {
        let result = sqlx::query(
            r#"
                SELECT
                    authenticator_pubkeys,
                    offchain_signer_commitment
                FROM accounts
                WHERE
                    leaf_index = $1
            "#,
        )
        .bind(leaf_index as i64)
        .fetch_optional(self.executor)
        .await?;

        result
            .map(|row| {
                let offchain_signer_commitment = Self::map_offchain_signer_commitment(&row)?;
                let pubkeys = Self::map_authenticator_pub_keys(&row)?;
                Ok((offchain_signer_commitment, pubkeys))
            })
            .transpose()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn get_account(self, leaf_index: u64) -> DBResult<Option<Account>> {
        let result = sqlx::query(
            r#"
                SELECT
                    leaf_index,
                    recovery_address,
                    authenticator_addresses,
                    authenticator_pubkeys,
                    offchain_signer_commitment,
                    latest_block_number,
                    latest_log_index
                FROM accounts
                WHERE
                    leaf_index = $1
            "#,
        )
        .bind(leaf_index as i64)
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_account(&row)).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "info", skip(self))]
    pub async fn insert(
        self,
        leaf_index: u64,
        recovery_address: &Address,
        authenticator_addresses: &[Address],
        authenticator_pubkeys: &[U256],
        offchain_signer_commitment: &U256,
        latest_block_number: u64,
        latest_log_index: u64,
    ) -> DBResult<()> {
        sqlx::query(
            r#"
                INSERT INTO accounts (
                    leaf_index,
                    recovery_address,
                    authenticator_addresses,
                    authenticator_pubkeys,
                    offchain_signer_commitment,
                    latest_block_number,
                    latest_log_index
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(leaf_index as i64)
        .bind(Self::address_to_u160(recovery_address))
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
        .bind(offchain_signer_commitment)
        .bind(latest_block_number as i64)
        .bind(latest_log_index as i64)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "info", skip(self))]
    pub async fn update_authenticator_at_index(
        self,
        leaf_index: u64,
        pubkey_id: u32,
        new_address: &Address,
        new_pubkey: &U256,
        new_commitment: &U256,
        latest_block_number: u64,
        latest_log_index: u64,
    ) -> DBResult<()> {
        // Update authenticator at specific index (pubkey_id)
        sqlx::query(
            r#"
                UPDATE accounts SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2::text[], to_jsonb($3::text), false),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2::text[], to_jsonb($4::text), false),
                    offchain_signer_commitment = $5,
                    latest_block_number = $6,
                    latest_log_index = $7
                WHERE
                    leaf_index = $1
            "#,
        )
            .bind(leaf_index as i64)
            .bind(format!("{{{pubkey_id}}}")) // JSONB path format: {0}, {1}, etc
            .bind(new_address.to_string())
            .bind(new_pubkey.to_string())
            .bind(new_commitment)
            .bind(latest_block_number as i64)
            .bind(latest_log_index as i64)
            .execute(self.executor)
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "info", skip(self))]
    pub async fn reset_authenticator(
        self,
        leaf_index: u64,
        new_address: &Address,
        new_pubkey: &U256,
        new_commitment: &U256,
        latest_block_number: u64,
        latest_log_index: u64,
    ) -> DBResult<()> {
        // Reset all authenticators to single one
        sqlx::query(
            r#"
                UPDATE accounts SET
                    authenticator_addresses = $2,
                    authenticator_pubkeys = $3,
                    offchain_signer_commitment = $4,
                    latest_block_number = $5,
                    latest_log_index = $6
                WHERE
                    leaf_index = $1
            "#,
        )
        .bind(leaf_index as i64)
        .bind(Json(
            [new_address]
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>(),
        ))
        .bind(Json(
            [new_pubkey]
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
        ))
        .bind(new_commitment)
        .bind(latest_block_number as i64)
        .bind(latest_log_index as i64)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "info", skip(self))]
    pub async fn insert_authenticator_at_index(
        self,
        leaf_index: u64,
        pubkey_id: u32,
        new_address: &Address,
        new_pubkey: &U256,
        new_commitment: &U256,
        latest_block_number: u64,
        latest_log_index: u64,
    ) -> DBResult<()> {
        // Ensure arrays are large enough and insert at specific index
        sqlx::query(
            r#"
                UPDATE accounts SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2::text[], to_jsonb($3::text), true),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2::text[], to_jsonb($4::text), true),
                    offchain_signer_commitment = $5,
                    latest_block_number = $6,
                    latest_log_index = $7
                WHERE
                    leaf_index = $1
            "#,
        )
            .bind(leaf_index as i64)
            .bind(format!("{{{pubkey_id}}}"))
            .bind(new_address.to_string())
            .bind(new_pubkey.to_string())
            .bind(new_commitment)
            .bind(latest_block_number as i64)
            .bind(latest_log_index as i64)
            .execute(self.executor)
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "info", skip(self))]
    pub async fn remove_authenticator_at_index(
        self,
        leaf_index: u64,
        pubkey_id: u32,
        new_commitment: &U256,
        latest_block_number: u64,
        latest_log_index: u64,
    ) -> DBResult<()> {
        // Remove authenticator at specific index by setting to null
        sqlx::query(
            r#"
                UPDATE accounts SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2::text[], 'null'::jsonb, false),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2::text[], 'null'::jsonb, false),
                    offchain_signer_commitment = $3,
                    latest_block_number = $4,
                    latest_log_index = $5
                WHERE
                    leaf_index = $1
            "#,
        )
        .bind(leaf_index as i64)
        .bind(format!("{{{pubkey_id}}}"))
        .bind(new_commitment)
        .bind(latest_block_number as i64)
        .bind(latest_log_index as i64)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    /// Get leaf indices from accounts where latest event is after the given event_id
    #[instrument(level = "info", skip(self))]
    pub async fn get_after_event<T: Into<AccountLatestEventId> + fmt::Debug>(
        self,
        event_id: T,
    ) -> DBResult<Vec<u64>> {
        let event_id = event_id.into();
        let rows = sqlx::query(
            r#"
                SELECT leaf_index
                FROM accounts
                WHERE (latest_block_number > $1)
                   OR (latest_block_number = $1 AND latest_log_index > $2)
                ORDER BY leaf_index
            "#,
        )
        .bind(event_id.latest_block_number as i64)
        .bind(event_id.latest_log_index as i64)
        .fetch_all(self.executor)
        .await?;

        rows.iter().map(Self::map_leaf_index).collect()
    }

    /// Delete accounts where latest event is after the given event_id
    #[instrument(level = "info", skip(self))]
    pub async fn delete_after_event<T: Into<AccountLatestEventId> + fmt::Debug>(
        self,
        event_id: T,
    ) -> DBResult<u64> {
        let event_id = event_id.into();
        let result = sqlx::query(
            r#"
                DELETE FROM accounts
                WHERE (latest_block_number > $1)
                   OR (latest_block_number = $1 AND latest_log_index > $2)
            "#,
        )
        .bind(event_id.latest_block_number as i64)
        .bind(event_id.latest_log_index as i64)
        .execute(self.executor)
        .await?;

        Ok(result.rows_affected())
    }

    fn map_account(row: &PgRow) -> DBResult<Account> {
        Ok(Account {
            leaf_index: Self::map_leaf_index(row)?,
            recovery_address: Self::map_recovery_address(row)?,
            authenticator_addresses: Self::map_authenticator_addresses(row)?,
            authenticator_pubkeys: Self::map_authenticator_pub_keys(row)?,
            offchain_signer_commitment: Self::map_offchain_signer_commitment(row)?,
            latest_event_id: Self::map_latest_event_id(row)?,
        })
    }

    fn map_leaf_index(row: &PgRow) -> DBResult<u64> {
        Ok(row.get::<i64, _>("leaf_index") as u64)
    }

    fn map_recovery_address(row: &PgRow) -> DBResult<Address> {
        Ok(Address::from(row.get::<U160, _>("recovery_address")))
    }

    fn map_offchain_signer_commitment(row: &PgRow) -> DBResult<U256> {
        Ok(row.get::<U256, _>("offchain_signer_commitment"))
    }

    /// Maps authenticator addresses from DB JSON into the full slot list stored for the account.
    ///
    /// Removed authenticators are preserved as `None` entries so caller logic keeps slot positions.
    fn map_authenticator_addresses(row: &PgRow) -> DBResult<Vec<Option<Address>>> {
        Ok(row
            .get::<Json<Vec<Option<String>>>, _>("authenticator_addresses")
            .0
            .iter()
            .map(|opt| opt.as_ref().and_then(|value| value.parse::<Address>().ok()))
            .collect())
    }

    /// Maps authenticator public keys from DB JSON into the full slot list stored for the account.
    ///
    /// Removed authenticators are preserved as `None` entries so caller logic keeps slot positions.
    fn map_authenticator_pub_keys(row: &PgRow) -> DBResult<Vec<Option<U256>>> {
        Ok(row
            .get::<Json<Vec<Option<String>>>, _>("authenticator_pubkeys")
            .0
            .iter()
            .map(|opt| opt.as_ref().and_then(|value| value.parse::<U256>().ok()))
            .collect())
    }

    fn map_latest_event_id(row: &PgRow) -> DBResult<AccountLatestEventId> {
        Ok(AccountLatestEventId {
            latest_block_number: row.get::<i64, _>("latest_block_number") as u64,
            latest_log_index: row.get::<i64, _>("latest_log_index") as u64,
        })
    }

    fn address_to_u160(address: &Address) -> U160 {
        (*address).into()
    }
}
