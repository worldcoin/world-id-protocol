use alloy::primitives::{Address, U256};
use sqlx::{Postgres, Row, types::Json};

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
    ) -> anyhow::Result<Option<(U256, Vec<U256>)>> {
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

        Ok(result.map(|row| {
            let offchain_signer_commitment = row.get::<U256, _>("offchain_signer_commitment");
            let pubkeys: Vec<U256> = row
                .get::<Json<Vec<String>>, _>("authenticator_pubkeys")
                .0
                .iter()
                .filter_map(|s| s.parse::<U256>().ok())
                .collect();
            (offchain_signer_commitment, pubkeys)
        }))
    }

    pub async fn insert(
        self,
        leaf_index: &U256,
        recovery_address: &Address,
        authenticator_addresses: &[Address],
        authenticator_pubkeys: &[U256],
        offchain_signer_commitment: &U256,
    ) -> anyhow::Result<()> {
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
        .bind(recovery_address.as_slice())
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
    ) -> anyhow::Result<()> {
        // Update authenticator at specific index (pubkey_id)
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), false),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), false),
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
    ) -> anyhow::Result<()> {
        // Reset all authenticators to single one
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = $2
                    authenticator_pubkeys = $3,
                    offchain_signer_commitment = $4
                WHERE
                    leaf_index = $1
            "#,
            self.table_name,
        ))
        .bind(leaf_index)
        .bind(Json(
            vec![new_address]
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>(),
        ))
        .bind(Json(
            vec![new_pubkey]
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
    ) -> anyhow::Result<()> {
        // Ensure arrays are large enough and insert at specific index
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2, to_jsonb($3::text), true),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, to_jsonb($4::text), true),
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
    ) -> anyhow::Result<()> {
        // Remove authenticator at specific index by setting to null
        sqlx::query(&format!(
            r#"
                UPDATE {} SET
                    authenticator_addresses = jsonb_set(authenticator_addresses, $2, 'null'::jsonb, false),
                    authenticator_pubkeys = jsonb_set(authenticator_pubkeys, $2, 'null'::jsonb, false),
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
}
