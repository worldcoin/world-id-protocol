use crate::{
    create_batcher::CreateBatcherHandle,
    ops_batcher::OpsBatcherHandle,
    request_tracker::{RequestKind, RequestState},
    ErrorResponse as ApiError,
};
use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use lru::LruCache;
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Maximum number of authenticators per account (matches contract default).
pub(crate) const MAX_AUTHENTICATORS: u32 = 7;

/// Cached root validity with optional expiration.
#[derive(Clone, Debug)]
pub(crate) struct RootCacheEntry {
    /// Whether the root was valid when cached.
    pub(crate) valid: bool,
    /// Optional unix timestamp (seconds) after which the cache entry is stale.
    pub(crate) expires_at: Option<U256>,
}

impl RootCacheEntry {
    /// Build a new cache entry.
    pub(crate) fn new(valid: bool, expires_at: Option<U256>) -> Self {
        Self { valid, expires_at }
    }

    /// Returns true when the cache entry should be considered fresh (not expired).
    pub(crate) fn is_fresh(&self, now: U256) -> bool {
        self.expires_at.map(|ts| ts > now).unwrap_or(true)
    }
}

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
    /// LRU cache of roots with optional expiration.
    pub(crate) root_cache: Arc<Mutex<LruCache<U256, RootCacheEntry>>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RequestStatusResponse {
    pub(crate) request_id: String,
    pub(crate) kind: RequestKind,
    pub(crate) status: RequestState,
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;
