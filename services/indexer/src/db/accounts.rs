use alloy::primitives::{Address, U160, U256};
use sqlx::{Postgres, Row, postgres::PgRow, types::Json};
use tracing::instrument;

use crate::db::DBResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub leaf_index: U256,
    pub recovery_address: Address,
    pub authenticator_addresses: Vec<Address>,
    pub authenticator_pubkeys: Vec<U256>,
    pub offchain_signer_commitment: U256,
}

pub struct Accounts<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    executor: E,
    table_name: String,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, E> Accounts<'a, E>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            table_name: "accounts".to_string(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn get_offchain_signer_commitment_and_authenticator_pubkeys_by_leaf_index(
        self,
        leaf_index: &U256,
    ) -> DBResult<Option<(U256, Vec<U256>)>> {
        let result = sqlx::query(&format!(
            r#"
                                SELECT
                                    authenticator_pubkeys,
                                    offchain_signer_commitment
                                FROM {}
                                WHERE
                                    leaf_index = $1
                            "#,
            self.table_name
        ))
        .bind(leaf_index)
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

    pub async fn get_account(self, leaf_index: &U256) -> DBResult<Option<Account>> {
        let result = sqlx::query(&format!(
            r#"
                                SELECT
                                    leaf_index,
                                    recovery_address,
                                    authenticator_addresses,
                                    authenticator_pubkeys,
                                    offchain_signer_commitment
                                FROM {}
                                WHERE
                                    leaf_index = $1
                            "#,
            self.table_name
        ))
        .bind(leaf_index)
        .fetch_optional(self.executor)
        .await?;

        result.map(|row| Self::map_account(&row)).transpose()
    }

    #[instrument(level = "info", skip(self))]
    pub async fn insert(
        self,
        leaf_index: &U256,
        recovery_address: &Address,
        authenticator_addresses: &[Address],
        authenticator_pubkeys: &[U256],
        offchain_signer_commitment: &U256,
    ) -> DBResult<()> {
        sqlx::query(&format!(
            r#"
                INSERT INTO {} (
                    leaf_index,
                    recovery_address,
                    authenticator_addresses,
                    authenticator_pubkeys,
                    offchain_signer_commitment
                ) VALUES ($1, $2, $3, $4, $5)
            "#,
            self.table_name,
        ))
        .bind(leaf_index)
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
        .execute(self.executor)
        .await?;
        Ok(())
    }

    pub async fn update_authenticator_at_index(
        self,
        leaf_index: &U256,
        pubkey_id: u32,
        new_address: &Address,
        new_pubkey: &U256,
        new_commitment: &U256,
    ) -> DBResult<()> {
        // Update authenticator at specific index (pubkey_id)
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2::text[], to_jsonb($3::text), false),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2::text[], to_jsonb($4::text), false),
                    offchain_signer_commitment = $5
                WHERE
                    leaf_index = $1
            "#,
            self.table_name,
        ))
            .bind(leaf_index)
            .bind(format!("{{{pubkey_id}}}")) // JSONB path format: {0}, {1}, etc
            .bind(new_address.to_string())
            .bind(new_pubkey.to_string())
            .bind(new_commitment)
            .execute(self.executor)
            .await?;
        Ok(())
    }

    pub async fn reset_authenticator(
        self,
        leaf_index: &U256,
        new_address: &Address,
        new_pubkey: &U256,
        new_commitment: &U256,
    ) -> DBResult<()> {
        // Reset all authenticators to single one
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = $2,
                    authenticator_pubkeys = $3,
                    offchain_signer_commitment = $4
                WHERE
                    leaf_index = $1
            "#,
            self.table_name,
        ))
        .bind(leaf_index)
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
        .execute(self.executor)
        .await?;
        Ok(())
    }

    pub async fn insert_authenticator_at_index(
        self,
        leaf_index: &U256,
        pubkey_id: u32,
        new_address: &Address,
        new_pubkey: &U256,
        new_commitment: &U256,
    ) -> DBResult<()> {
        // Ensure arrays are large enough and insert at specific index
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2::text[], to_jsonb($3::text), true),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2::text[], to_jsonb($4::text), true),
                    offchain_signer_commitment = $5
                WHERE
                    leaf_index = $1
            "#,
            self.table_name,
        ))
            .bind(leaf_index)
            .bind(format!("{{{pubkey_id}}}"))
            .bind(new_address.to_string())
            .bind(new_pubkey.to_string())
            .bind(new_commitment)
            .execute(self.executor)
            .await?;
        Ok(())
    }

    pub async fn remove_authenticator_at_index(
        self,
        leaf_index: &U256,
        pubkey_id: u32,
        new_commitment: &U256,
    ) -> DBResult<()> {
        // Remove authenticator at specific index by setting to null
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2::text[], 'null'::jsonb, false),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2::text[], 'null'::jsonb, false),
                    offchain_signer_commitment = $3
                WHERE
                    leaf_index = $1
            "#,
            self.table_name,
        ))
        .bind(leaf_index)
        .bind(format!("{{{pubkey_id}}}"))
        .bind(new_commitment)
        .execute(self.executor)
        .await?;
        Ok(())
    }

    fn map_account(row: &PgRow) -> DBResult<Account> {
        Ok(Account {
            leaf_index: Self::map_leaf_index(row)?,
            recovery_address: Self::map_recovery_address(row)?,
            authenticator_addresses: Self::map_authenticator_addresses(row)?,
            authenticator_pubkeys: Self::map_authenticator_pub_keys(row)?,
            offchain_signer_commitment: Self::map_offchain_signer_commitment(row)?,
        })
    }

    fn map_leaf_index(row: &PgRow) -> DBResult<U256> {
        Ok(row.get::<U256, _>("leaf_index"))
    }

    fn map_recovery_address(row: &PgRow) -> DBResult<Address> {
        Ok(Address::from(row.get::<U160, _>("recovery_address")))
    }

    fn map_offchain_signer_commitment(row: &PgRow) -> DBResult<U256> {
        Ok(row.get::<U256, _>("offchain_signer_commitment"))
    }

    fn map_authenticator_addresses(row: &PgRow) -> DBResult<Vec<Address>> {
        Ok(row
            .get::<Json<Vec<Option<String>>>, _>("authenticator_addresses")
            .0
            .iter()
            .filter_map(|opt| opt.as_ref()?.parse::<Address>().ok())
            .collect())
    }

    fn map_authenticator_pub_keys(row: &PgRow) -> DBResult<Vec<U256>> {
        Ok(row
            .get::<Json<Vec<Option<String>>>, _>("authenticator_pubkeys")
            .0
            .iter()
            .filter_map(|opt| opt.as_ref()?.parse::<U256>().ok())
            .collect())
    }

    fn address_to_u160(address: &Address) -> U160 {
        (*address).into()
    }
}
