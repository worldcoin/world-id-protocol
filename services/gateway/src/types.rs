use crate::{create_batcher::CreateBatcherHandle, ops_batcher::OpsBatcherHandle};
use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use lru::LruCache;
use parking_lot::Mutex;
use std::sync::Arc;

/// Maximum number of authenticators per account (matches contract default).
pub(crate) const MAX_AUTHENTICATORS: u32 = 7;

/// Shared application state for gateway handlers.
#[derive(Clone)]
pub(crate) struct AppState {
    /// World ID Registry contract address.
    pub(crate) registry_addr: Address,
    /// Ethereum RPC provider.
    pub(crate) provider: DynProvider,
    /// Background batcher for create-account.
    pub(crate) batcher: CreateBatcherHandle,
    /// Background batcher for ops (insert/remove/recover/update).
    pub(crate) ops_batcher: OpsBatcherHandle,
    /// LRU cache of valid roots to their expiration timestamps.
    pub(crate) root_cache: Arc<Mutex<LruCache<U256, U256>>>,
}
