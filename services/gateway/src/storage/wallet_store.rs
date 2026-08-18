use std::time::Duration;

use alloy::primitives::{Address, TxHash};
use redis::{AsyncTypedCommands, Client, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{batch_type::BatchType, error::GatewayResult};

const RESERVATION_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum WalletTransaction {
    Reserved {
        reservation_id: Uuid,
    },
    Submitted {
        reservation_id: Uuid,
        tx_hash: TxHash,
        request_ids: Vec<String>,
        batch_type: BatchType,
        submitted_at: u64,
    },
}

/// Redis storage for transaction-wallet reservations.
#[derive(Clone)]
pub(crate) struct WalletStore {
    manager: ConnectionManager,
}

impl WalletStore {
    /// Connects to Redis and creates a cloneable connection manager.
    pub(crate) async fn connect(redis_url: &str) -> GatewayResult<Self> {
        let client = Client::open(redis_url)?;
        let manager = ConnectionManager::new(client).await?;
        Ok(Self { manager })
    }

    /// Atomically reserves `wallet` under
    /// `gateway:wallet_transaction:{wallet_address}`.
    ///
    /// The reservation expires after [`RESERVATION_TTL`]. Returns `false`
    /// without changing storage when the wallet is already reserved or has a
    /// submitted transaction.
    pub(crate) async fn reserve(
        &self,
        wallet: Address,
        reservation_id: Uuid,
    ) -> GatewayResult<bool> {
        let value = serde_json::to_string(&WalletTransaction::Reserved { reservation_id })?;
        let mut manager = self.manager.clone();
        let inserted: Option<String> = redis::cmd("SET")
            .arg(Self::key(wallet))
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(RESERVATION_TTL.as_secs())
            .query_async(&mut manager)
            .await?;
        Ok(inserted.is_some())
    }

    /// Replaces a matching reservation at
    /// `gateway:wallet_transaction:{wallet_address}` with its submitted transaction.
    ///
    /// Returns an error if the wallet is not reserved with `reservation_id`.
    pub(crate) async fn mark_submitted(
        &self,
        wallet: Address,
        reservation_id: Uuid,
        tx_hash: TxHash,
        request_ids: Vec<String>,
        batch_type: BatchType,
        submitted_at: u64,
    ) -> GatewayResult<WalletTransaction> {
        let expected = serde_json::to_string(&WalletTransaction::Reserved { reservation_id })?;
        let transaction = WalletTransaction::Submitted {
            reservation_id,
            tx_hash,
            request_ids,
            batch_type,
            submitted_at,
        };
        let submitted = serde_json::to_string(&transaction)?;
        let mut manager = self.manager.clone();
        let _: () = redis::Script::new(
            r#"
            if redis.call('GET', KEYS[1]) ~= ARGV[1] then
                return redis.error_reply('wallet reservation changed before submission')
            end
            redis.call('SET', KEYS[1], ARGV[2])
            return redis.status_reply('OK')
            "#,
        )
        .key(Self::key(wallet))
        .arg(expected)
        .arg(submitted)
        .invoke_async(&mut manager)
        .await?;

        Ok(transaction)
    }

    /// Deletes `gateway:wallet_transaction:{wallet_address}` when it contains
    /// the matching reservation ID.
    ///
    /// Succeeds when no transaction is stored for the wallet and returns an
    /// error when a different reservation or submission is stored.
    pub(crate) async fn release_reservation(
        &self,
        wallet: Address,
        reservation_id: Uuid,
    ) -> GatewayResult<()> {
        self.release_if_matches(wallet, &WalletTransaction::Reserved { reservation_id })
            .await
    }

    /// Deletes `gateway:wallet_transaction:{wallet_address}` when it contains
    /// the matching reservation ID and transaction hash.
    ///
    /// Succeeds when no transaction is stored for the wallet and returns an
    /// error when a different reservation or submission is stored.
    pub(crate) async fn release_submission(
        &self,
        wallet: Address,
        reservation_id: Uuid,
        tx_hash: TxHash,
    ) -> GatewayResult<()> {
        let mut manager = self.manager.clone();
        let _: i64 = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return 0
            end
            local decoded = cjson.decode(current)
            if decoded.state ~= 'submitted'
                or decoded.reservation_id ~= ARGV[1]
                or decoded.tx_hash ~= ARGV[2] then
                return redis.error_reply('wallet transaction changed before release')
            end
            redis.call('DEL', KEYS[1])
            return 1
            "#,
        )
        .key(Self::key(wallet))
        .arg(reservation_id.to_string())
        .arg(tx_hash.to_string())
        .invoke_async(&mut manager)
        .await?;
        Ok(())
    }

    /// Loads multiple `gateway:wallet_transaction:{wallet_address}` records in
    /// one Redis round trip.
    ///
    /// Results preserve the order of `wallets`; wallets without a stored
    /// transaction are represented as `None`.
    pub(crate) async fn transactions(
        &self,
        wallets: &[Address],
    ) -> GatewayResult<Vec<Option<WalletTransaction>>> {
        if wallets.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<String> = wallets.iter().copied().map(Self::key).collect();
        let mut manager = self.manager.clone();
        let values: Vec<Option<String>> = manager.mget(keys).await?;
        values
            .into_iter()
            .map(|value| {
                value
                    .map(|value| serde_json::from_str(&value).map_err(Into::into))
                    .transpose()
            })
            .collect()
    }

    async fn release_if_matches(
        &self,
        wallet: Address,
        expected: &WalletTransaction,
    ) -> GatewayResult<()> {
        let expected = serde_json::to_string(expected)?;
        let mut manager = self.manager.clone();
        let _: i64 = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return 0
            end
            if current ~= ARGV[1] then
                return redis.error_reply('wallet transaction changed before release')
            end
            redis.call('DEL', KEYS[1])
            return 1
            "#,
        )
        .key(Self::key(wallet))
        .arg(expected)
        .invoke_async(&mut manager)
        .await?;
        Ok(())
    }

    fn key(wallet: Address) -> String {
        format!("gateway:wallet_transaction:{wallet}")
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use testcontainers_modules::{
        redis::{REDIS_PORT, Redis},
        testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
    };

    use super::*;

    async fn store() -> (WalletStore, ContainerAsync<Redis>) {
        let container = Redis::default()
            .with_tag("latest")
            .start()
            .await
            .expect("failed to start Redis container");
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(REDIS_PORT).await.unwrap();
        let store = WalletStore::connect(&format!("redis://{host}:{port}"))
            .await
            .unwrap();
        (store, container)
    }

    #[test]
    fn submitted_records_require_batch_metadata() {
        let transaction = WalletTransaction::Submitted {
            reservation_id: Uuid::new_v4(),
            tx_hash: TxHash::repeat_byte(0x22),
            request_ids: vec!["request-1".to_string()],
            batch_type: BatchType::Ops,
            submitted_at: 100,
        };
        let value = serde_json::to_value(transaction).unwrap();
        assert_eq!(value["batch_type"], "ops");
        assert_eq!(value["submitted_at"], 100);

        for field in ["batch_type", "submitted_at"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<WalletTransaction>(missing).is_err());
        }
    }

    #[tokio::test]
    async fn reservations_transition_to_hash_and_release_conditionally() {
        let (store, _redis) = store().await;
        let wallet = address!("1111111111111111111111111111111111111111");
        let reservation_id = Uuid::new_v4();
        let tx_hash = TxHash::repeat_byte(0x22);

        assert!(store.reserve(wallet, reservation_id).await.unwrap());
        let mut manager = store.manager.clone();
        let ttl: i64 = redis::cmd("TTL")
            .arg(WalletStore::key(wallet))
            .query_async(&mut manager)
            .await
            .unwrap();
        assert!(ttl > 0 && ttl <= RESERVATION_TTL.as_secs() as i64);
        assert!(!store.reserve(wallet, Uuid::new_v4()).await.unwrap());
        let submitted = store
            .mark_submitted(
                wallet,
                reservation_id,
                tx_hash,
                vec!["request-1".to_string()],
                BatchType::Ops,
                100,
            )
            .await
            .unwrap();
        assert_eq!(
            store.transactions(&[wallet]).await.unwrap(),
            [Some(submitted.clone())]
        );
        store
            .release_submission(wallet, reservation_id, tx_hash)
            .await
            .unwrap();
        assert_eq!(store.transactions(&[wallet]).await.unwrap(), [None]);
    }
}
