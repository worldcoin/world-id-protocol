use alloy::primitives::{Address, U256};
use sqlx::{PgPool, types::Json};

pub struct Accounts<'a> {
    pool: &'a PgPool,
    table_name: String,
}

impl<'a> Accounts<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self {
            pool,
            table_name: "accounts".to_string(),
        }
    }

    pub async fn insert(
        &self,
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
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_authenticator_at_index(
        &self,
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
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn insert_authenticator_at_index(
        &self,
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
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn remove_authenticator_at_index(
        &self,
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
        .execute(self.pool)
        .await?;
        Ok(())
    }
}
