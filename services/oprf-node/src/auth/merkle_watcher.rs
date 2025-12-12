//! This module provides functionality for watching and validating Merkle roots. It includes:
//!
//! - A `MerkleWatcher` trait for services that validate Merkle roots.
//! - A `MerkleRootStore` for storing and Merkle roots with timestamps.
//!
//! Current `MerkleWatcher` implementations:
//! - alloy (uses the alloy crate to interact with smart contracts)
//! - test (contains initially provided merkle roots)

use std::{collections::HashMap, sync::Arc, time::SystemTime};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider as _},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent as _,
};
use eyre::Context as _;
use futures::StreamExt as _;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use world_id_primitives::FieldElement;

sol! {
    #[sol(rpc)]
    contract AccountRegistry {
        function isValidRoot(uint256 root) external view returns (bool);
        function currentRoot() external view returns (uint256);
    }
    event RootRecorded(uint256 indexed root, uint256 timestamp, uint256 indexed rootEpoch);
}

/// Error returned by the [`MerkleWatcher`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum MerkleWatcherError {
    #[error("invalid merkle root")]
    InvalidMerkleRoot,
    #[error(transparent)]
    AlloyError(#[from] alloy::contract::Error),
}

/// Monitors merkle roots from an on-chain AccountRegistry contract.
///
/// Subscribes to blockchain events and maintains a store of valid merkle roots.
#[derive(Clone)]
pub(crate) struct MerkleWatcher {
    merkle_root_store: Arc<Mutex<MerkleRootStore>>,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
}

impl MerkleWatcher {
    /// Initializes the merkle watcher and starts listening for events.
    ///
    /// Connects to the blockchain via WebSocket, fetches the current merkle root,
    /// and spawns a background task to monitor for new `RootRecorded` events.
    ///
    /// # Arguments
    /// * `contract_address` - Address of the AccountRegistry contract
    /// * `max_store_size` - Maximum number of keys to store
    /// * `provider` - Alloy provider that establishes connection to chain. Doesn't need a signing key.
    /// * `cancellation_token` - CancellationToken to cancel the service in case of an error
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        max_store_size: usize,
        provider: DynProvider,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        let contract = AccountRegistry::new(contract_address, provider.clone());

        tracing::info!("get current root...");
        let current_root = contract.currentRoot().call().await?;
        tracing::info!("root = {current_root}");

        let merkle_root_store = Arc::new(Mutex::new(
            MerkleRootStore::new(
                HashMap::from([(current_root.try_into()?, 0)]), // insert current root with 0 timestamp so it is oldest
                max_store_size,
            )
            .context("while building merkle root store")?,
        ));
        let merkle_root_store_clone = Arc::clone(&merkle_root_store);

        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(RootRecorded::SIGNATURE_HASH);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        tokio::spawn(async move {
            // shutdown service if merkle watcher encounters an error and drops this guard
            let _drop_guard = cancellation_token.drop_guard();
            while let Some(log) = stream.next().await {
                match RootRecorded::decode_log(log.as_ref()) {
                    Ok(event) => {
                        tracing::info!("got root {} timestamp {}", event.root, event.timestamp);
                        if let Ok(timestamp) = u64::try_from(event.timestamp) {
                            merkle_root_store_clone.lock().insert(
                                event.root.try_into().expect("root is in field"),
                                timestamp,
                            );
                        } else {
                            tracing::warn!("AccountRegistry send root with timestamp > u64");
                        }
                    }
                    Err(err) => {
                        tracing::warn!("failed to decode contract event: {err:?}");
                    }
                }
            }
        });

        Ok(Self {
            merkle_root_store,
            provider: provider.erased(),
            contract_address,
        })
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn is_root_valid(&self, root: FieldElement) -> Result<(), MerkleWatcherError> {
        {
            let store = self.merkle_root_store.lock();
            // first check if the merkle root is already registered
            if store.contains_root(root) {
                tracing::trace!("root was in store");
                tracing::trace!("root valid: true");
                return Ok(());
            }
        }
        tracing::debug!("check in contract");
        let contract = AccountRegistry::new(self.contract_address, self.provider.clone());
        let valid = contract.isValidRoot(root.into()).call().await?;
        {
            tracing::debug!("add root to store");
            let mut store = self.merkle_root_store.lock();
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time is after unix epoch")
                .as_secs();
            store.insert(root, timestamp);
        }
        tracing::debug!("root valid: {valid}");
        return if valid {
            Ok(())
        } else {
            Err(MerkleWatcherError::InvalidMerkleRoot)
        };
    }
}

/// Stores Merkle roots with associated timestamps.
///
/// Maintains a HashMap of root -> timestamp, automatically keeping the most recent roots
/// up to a configured maximum. Old roots are dropped when the store exceeds capacity.
#[derive(Debug, Clone)]
pub(crate) struct MerkleRootStore {
    store: HashMap<FieldElement, u64>,
    max_merkle_store_size: usize,
}

impl MerkleRootStore {
    /// Creates a new Merkle root store.
    ///
    /// Clips the store if it exceeds `max_merkle_store_size`.
    /// Fails if `max_merkle_store_size` is 0.
    pub(crate) fn new(
        store: HashMap<FieldElement, u64>,
        max_merkle_store_size: usize,
    ) -> eyre::Result<Self> {
        if max_merkle_store_size == 0 {
            eyre::bail!("Max merkle store size must be > 0");
        }
        if store.len() > max_merkle_store_size {
            eyre::bail!("initial store must be smaller than max");
        }
        tracing::info!("starting with store size: {}", store.len());
        Ok(Self {
            store,
            max_merkle_store_size,
        })
    }

    /// Inserts a new Merkle root.
    ///
    /// If the root already exists, it replaces the previous timestamp.
    /// Automatically drops the oldest root if the store exceeds the configured maximum size.
    #[instrument(level = "trace", skip(self))]
    pub(crate) fn insert(&mut self, root: FieldElement, timestamp: u64) {
        if self.store.insert(root, timestamp).is_some() {
            tracing::debug!("root {root} already registered - replaced");
        } else {
            tracing::trace!("registered new root: {root}");
            if self.store.len() > self.max_merkle_store_size {
                // find root with oldest timestamp
                let oldest_root = self
                    .store
                    .iter()
                    .min_by_key(|(_, timestamp)| *timestamp)
                    .map(|(root, _)| *root)
                    .expect("store is not empty");
                tracing::debug!("store size exceeded, dropping oldest root: {oldest_root}");
                // drop the oldest root
                let dropped = self.store.remove(&oldest_root).expect("store not empty");
                tracing::trace!("dropped {dropped}");
            }
        }
    }

    /// Checks if the store contains a Merkle root
    ///
    /// Returns `true` if the root exists, `false` otherwise.
    pub(crate) fn contains_root(&self, root: FieldElement) -> bool {
        self.store.contains_key(&root)
    }
}
