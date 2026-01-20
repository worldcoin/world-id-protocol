use crate::{create_batcher::CreateBatcherHandle, ops_batcher::OpsBatcherHandle};
use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use moka::{Expiry, future::Cache};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum number of authenticators per account (matches contract default).
pub(crate) const MAX_AUTHENTICATORS: u32 = 7;

/// Custom expiry policy for root cache entries.
///
/// The cache stores `(root, expires_at)` pairs where `expires_at` is a Unix
/// timestamp. This policy computes the TTL dynamically based on that timestamp.
pub(crate) struct RootExpiry;

impl RootExpiry {
    /// Compute duration until expiration from a Unix timestamp.
    fn duration_until(expires_at: &U256) -> Option<Duration> {
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let expires_at_secs: u64 = (*expires_at).try_into().ok()?;

        if expires_at_secs <= now_secs {
            // Already expired — evict immediately
            Some(Duration::ZERO)
        } else {
            Some(Duration::from_secs(expires_at_secs - now_secs))
        }
    }
}

impl Expiry<U256, U256> for RootExpiry {
    fn expire_after_create(
        &self,
        _key: &U256,
        expires_at: &U256,
        _created_at: Instant,
    ) -> Option<Duration> {
        Self::duration_until(expires_at)
    }

    fn expire_after_read(
        &self,
        _key: &U256,
        _value: &U256,
        _read_at: Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        // Don't change expiration on read — keep original TTL
        duration_until_expiry
    }

    fn expire_after_update(
        &self,
        _key: &U256,
        expires_at: &U256,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        // Recalculate TTL from updated expiration timestamp
        Self::duration_until(expires_at)
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
    /// Cache of valid roots to their expiration timestamps.
    pub(crate) root_cache: Cache<U256, U256>,
}
