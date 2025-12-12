use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, LogData, U256},
    providers::{DynProvider, Provider as _},
    rpc::types::{Filter, Log},
    sol,
    sol_types::SolEvent,
};
use ark_ff::PrimeField;
use eyre::Context as _;
use futures::StreamExt as _;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

// TODO the credential issuer schema registry is already included in world-id-core = { workspace = true }. Unfortunately, it is not public therefore we cannot reuse sol script. For the time being we paste it here but we want to use the same abi for both places.
sol! {
    #[sol(rpc)]
    contract CredentialSchemaIssuerRegistry {
        function issuerSchemaIdToPubkey(uint256 issuerSchemaId) public view returns (PubkeySol memory);
    }
    struct PubkeySol {
        uint256 x;
        uint256 y;
    }
    event IssuerSchemaRemoved(uint256 indexed issuerSchemaId, PubkeySol pubkey, address signer);
    event IssuerSchemaPubkeyUpdated(uint256 indexed issuerSchemaId, PubkeySol oldPubkey, PubkeySol newPubkey);
}

/// Error returned by the [`IssuerSchemaWatcher`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum IssuerSchemaWatcherError {
    /// Invalid credential issuer with id
    #[error("cannot find credential id: {0}")]
    InvalidCredentialId(U256),
    #[error(transparent)]
    AlloyError(#[from] alloy::contract::Error),
}

/// The EdDSA public-key of a issuer. We only need the x and y coordinates of the public-key for the Query proof.
#[derive(Clone, Debug)]
pub(crate) struct IssuerSchemaPublicKey {
    pub(crate) x: ark_babyjubjub::Fq,
    pub(crate) y: ark_babyjubjub::Fq,
}

/// Stores [`IssuerSchemaPublicKey`] and the timestamp of their latest use.
///
/// Maintains a `HashMap` mapping `issuer_schema_id` → `public_key`, automatically removing keys up to a configured maximum. Every time someone requests a specific ID, the implementation automatically updates the associated timestamp. If the store reaches its capacity, it will drop the oldest key with respect to usage and will remove all other keys older than a configured duration (this happens only when capacity is reached).
#[derive(Clone)]
struct IssuerPublicKeyStore {
    max_size: usize,
    max_age: Duration,
    keys: Arc<Mutex<HashMap<U256, (IssuerSchemaPublicKey, Instant)>>>,
}

impl IssuerPublicKeyStore {
    /// Creates a new [`IssuerPublicKeyStore`]
    fn new(max_size: usize, max_age: Duration) -> Self {
        Self {
            max_size,
            max_age,
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Inserts a new [`IssuerSchemaPublicKey`] with the provided id.
    ///
    /// If the stores keys exceed a defined maximum, will attempt to remove unused keys. We always drop the key that was not used for the longest time. Additionally, we remove all keys that were not used longer than a specified time. The new key's timestamp will be set to now.
    fn insert(&self, id: U256, key: IssuerSchemaPublicKey) {
        tracing::debug!("inserting issuer schema with id: {id}");
        let mut keys = self.keys.lock();
        if keys.insert(id, (key, Instant::now())).is_some() {
            tracing::warn!("overwriting existing key");
        }
        if keys.len() > self.max_size {
            tracing::debug!("cleanup cache, more than {}", self.max_size);
            // drop the oldest
            let oldest_root = keys
                .iter()
                .min_by_key(|(_, (_, instant))| *instant)
                .map(|(root, _)| *root)
                .expect("store is not empty");
            keys.remove(&oldest_root);
            // remove generally all that were not used longer than specified time
            keys.retain(|_, (_, t)| t.elapsed() < self.max_age);
            tracing::debug!("now has {} cached", keys.len());
        }
    }

    /// Tries to update a stored  [`IssuerSchemaPublicKey`].
    ///
    /// If the key is not in the store, we do nothing. If the key is in the store, we **don't** update its used timestamp. We only want to call this on chain events, which doesn't tell anything about usage.
    fn update(&self, id: U256, key: IssuerSchemaPublicKey) {
        let mut keys = self.keys.lock();
        if let Some((old_key, _)) = keys.get_mut(&id) {
            tracing::debug!("updating key");
            *old_key = key;
        } else {
            tracing::debug!("not in cache");
        }
    }

    /// Tries to remove a stored  [`IssuerSchemaPublicKey`].
    ///
    /// If the key is not in the store, we do nothing.
    fn remove(&self, id: U256) {
        let mut keys = self.keys.lock();
        if keys.remove(&id).is_some() {
            tracing::debug!("removed the key from cache")
        } else {
            tracing::debug!("not in cache");
        }
    }

    /// Tries to retrieve an [`IssuerSchemaPublicKey`] by the provided id.
    ///
    /// If not in store, return `None`. If the key is in the store, we update its associated timestamp.
    fn get(&self, id: U256) -> Option<IssuerSchemaPublicKey> {
        let mut keys = self.keys.lock();
        let (key, instant) = keys.get_mut(&id)?;
        *instant = Instant::now();
        Some(key.to_owned())
    }
}

impl TryFrom<PubkeySol> for IssuerSchemaPublicKey {
    type Error = eyre::Report;

    fn try_from(PubkeySol { x, y }: PubkeySol) -> Result<Self, Self::Error> {
        let x = ark_ff::BigInt(x.into_limbs());
        let y = ark_ff::BigInt(y.into_limbs());
        if ark_babyjubjub::Fq::MODULUS <= x || ark_babyjubjub::Fq::MODULUS <= y {
            eyre::bail!("couldn't convert public-key - coords don't fit into Fq")
        } else {
            Ok(Self {
                x: ark_babyjubjub::Fq::new(x),
                y: ark_babyjubjub::Fq::new(y),
            })
        }
    }
}

/// Monitors IssuerSchemaPublicKeys from an on-chain IssuerSchemaRegistry contract.
///
/// Subscribes to blockchain events and maintains a store of recently used [`IssuerSchemaPublicKey`]s. The watcher will lazy load the keys, meaning that at start-up the store is empty, and if user's request a specific key, we will go to chain and fetch it. The store size is configurable and can be set to high value as the keys are rather small. Additionally, keeps track of time of last use and, when exceeding the defined maximum store size, will drop keys that were not used for that timeframe.
///
/// Listens for `IssuerSchemaRemoved` and `IssuerSchemaPubkeyUpdated` events to update/remove currently stored keys.
#[derive(Clone)]
pub(crate) struct IssuerSchemaWatcher {
    issuer_key_store: IssuerPublicKeyStore,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
}

impl IssuerSchemaWatcher {
    /// Initializes the issuer schema watcher and starts listening for events.
    ///
    /// Connects to the blockchain via WebSocket and spawns a background task to monitor for new `IssuerSchemaRemoved` and `IssuerSchemaPubkeyUpdated` events.
    ///
    /// # Arguments
    /// * `contract_address` - Address of the IssuerSchemaRegistry contract
    /// * `max_store_size` - Maximum number of keys to store
    /// * `max_age` - When exceeding `max_store_size`, drop all keys that were not used longer than this threshold
    /// * `provider` - Alloy provider that establishes connection to chain. Doesn't need a signing key.
    /// * `cancellation_token` - CancellationToken to cancel the service in case of an error
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        max_store_size: usize,
        max_age: Duration,
        provider: DynProvider,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(vec![
                IssuerSchemaRemoved::SIGNATURE_HASH,
                IssuerSchemaPubkeyUpdated::SIGNATURE_HASH,
            ]);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        let issuer_schema_watcher = Self {
            issuer_key_store: IssuerPublicKeyStore::new(max_store_size, max_age),
            provider,
            contract_address,
        };
        tokio::spawn({
            let issuer_schema_watcher = issuer_schema_watcher.clone();
            async move {
                // shutdown service if merkle watcher encounters an error and drops this guard
                let _drop_guard = cancellation_token.drop_guard();
                while let Some(log) = stream.next().await {
                    match log.topic0() {
                        Some(&IssuerSchemaRemoved::SIGNATURE_HASH) => {
                            tracing::debug!("got schema removed log..");
                            if let Err(err) = issuer_schema_watcher.handle_remove(log) {
                                tracing::warn!("{err:?}");
                            }
                        }
                        Some(&IssuerSchemaPubkeyUpdated::SIGNATURE_HASH) => {
                            tracing::debug!("got schema update log..");
                            if let Err(err) = issuer_schema_watcher.handle_update(log) {
                                tracing::warn!("{err:?}");
                            }
                        }
                        x => {
                            tracing::warn!("unknown event: {x:?}");
                        }
                    }
                }
            }
        });
        Ok(issuer_schema_watcher)
    }

    /// Handles update events from chain.
    #[instrument(level = "debug", skip_all, fields(issuer_schema_id=tracing::field::Empty))]
    fn handle_update(&self, log: Log<LogData>) -> eyre::Result<()> {
        let key_update = log
            .log_decode()
            .context("while decoding key update event")?;
        let IssuerSchemaPubkeyUpdated {
            issuerSchemaId,
            oldPubkey: _,
            newPubkey,
        } = key_update.inner.data;
        let handle_span = tracing::Span::current();
        handle_span.record("issuer_schema_id", issuerSchemaId.to_string());
        tracing::debug!("got pub-key update for {issuerSchemaId} - let's see if we have it cached");
        match IssuerSchemaPublicKey::try_from(newPubkey) {
            Ok(key) => {
                self.issuer_key_store.update(issuerSchemaId, key);
            }
            Err(err) => {
                tracing::warn!("cannot update new key - removing instead: {err:?}");
                self.issuer_key_store.remove(issuerSchemaId);
            }
        }
        Ok(())
    }

    /// Handles remove events from chain.
    #[instrument(level = "debug", skip_all, fields(issuer_schema_id=tracing::field::Empty))]
    fn handle_remove(&self, log: Log<LogData>) -> eyre::Result<()> {
        let key_delete = log
            .log_decode()
            .context("while decoding key remove event")?;
        let IssuerSchemaRemoved {
            issuerSchemaId,
            pubkey: _,
            signer: _,
        } = key_delete.inner.data;
        let handle_span = tracing::Span::current();
        handle_span.record("issuer_schema_id", issuerSchemaId.to_string());
        tracing::debug!("got pub-key remove for {issuerSchemaId} - let's see if we have it cached");
        self.issuer_key_store.remove(issuerSchemaId);
        Ok(())
    }

    /// Tries to retrieve an [`IssuerSchemaPublicKey`] by the provided id from store.
    ///
    /// If the requested id is not in the store, will try to go to chain and load the key from there. If this key is also not found on chain, will return an error. If we manage to retrieve the key from chain, we add it to the store with a currently used timestamp (i.e., now) and return it.
    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn get_pubkey(
        &self,
        id: U256,
    ) -> Result<IssuerSchemaPublicKey, IssuerSchemaWatcherError> {
        tracing::trace!("checking issuer for id: {id}");
        if let Some(key) = self.issuer_key_store.get(id) {
            tracing::trace!("{id} is in cache!");
            return Ok(key);
        }
        tracing::debug!("issuer with id {id} not in cache.. going to chain..");
        // cache miss - go to chain
        let contract =
            CredentialSchemaIssuerRegistry::new(self.contract_address, self.provider.clone());
        let key = contract.issuerSchemaIdToPubkey(id).call().await?;
        if key.x == 0 && key.y == 0 {
            return Err(IssuerSchemaWatcherError::InvalidCredentialId(id));
        }
        match IssuerSchemaPublicKey::try_from(key) {
            Ok(key) => {
                self.issuer_key_store.insert(id, key.clone());
                Ok(key)
            }
            Err(err) => {
                tracing::warn!("got invalid key from chain: {err:?}");
                Err(IssuerSchemaWatcherError::InvalidCredentialId(id))
            }
        }
    }
}
