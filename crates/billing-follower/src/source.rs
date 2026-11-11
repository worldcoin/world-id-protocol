//! What the follower reads from the chain, independent of how it reads it.

use std::future::Future;

use alloy::primitives::{B256, U256};
use world_id_primitives::rp::RpId;

/// A block header, as far as the follower needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    /// The block number.
    pub number: u64,
    /// The block hash.
    pub hash: B256,
    /// The parent block's hash.
    pub parent_hash: B256,
    /// The block timestamp, in Unix seconds.
    pub timestamp: u64,
}

/// A Billing Contract event that changes the billing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingEvent {
    /// `Registered(rpId, periodStart, billingNullifier)`.
    Registered {
        /// The RP whose capacity the registration consumed.
        rp_id: RpId,
        /// The registration's billing period.
        period_start: u64,
        /// The registered `billingNullifier`.
        nullifier: U256,
    },
    /// `BilledRpUpdated(rpId, billed)`.
    BilledRpUpdated {
        /// The RP.
        rp_id: RpId,
        /// Whether the Contract now bills it.
        billed: bool,
    },
}

/// A Billing Contract log with its position in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainLog {
    /// The number of the block that emitted it.
    pub block_number: u64,
    /// The hash of that block.
    pub block_hash: B256,
    /// Its index within the block.
    pub log_index: u64,
    /// The decoded event.
    pub event: BillingEvent,
}

/// Which Billing Contract events a log query returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSet {
    /// Only `BilledRpUpdated`, for blocks before the earliest active period.
    BilledRps,
    /// `BilledRpUpdated` and `Registered`.
    All,
}

/// A failed chain read. The follower retries every one of them.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The call did not answer in time.
    #[error("{method} timed out")]
    Timeout {
        /// The JSON-RPC method.
        method: &'static str,
    },
    /// The call failed.
    #[error("{method} failed: {source}")]
    Rpc {
        /// The JSON-RPC method.
        method: &'static str,
        /// The transport or JSON-RPC error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The call answered with something the follower cannot use.
    #[error("{method} answered with {reason}")]
    Malformed {
        /// The JSON-RPC method.
        method: &'static str,
        /// What was wrong.
        reason: String,
    },
}

impl SourceError {
    /// The error class used as a metric label.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Timeout { .. } => "timeout",
            Self::Rpc { .. } => "rpc",
            Self::Malformed { .. } => "malformed",
        }
    }

    /// The JSON-RPC method that failed.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Timeout { method }
            | Self::Rpc { method, .. }
            | Self::Malformed { method, .. } => method,
        }
    }
}

/// Reads the Billing Contract's chain. [`crate::RpcSource`] implements it over JSON-RPC; another
/// source, e.g. a preconfirmation feed, can implement it too.
pub trait ChainSource: Send + Sync {
    /// The chain ID.
    fn chain_id(&self) -> impl Future<Output = Result<u64, SourceError>> + Send;

    /// The latest block.
    fn latest(&self) -> impl Future<Output = Result<BlockRef, SourceError>> + Send;

    /// The block at `number`, or `None` if the source does not have it yet.
    fn block(
        &self,
        number: u64,
    ) -> impl Future<Output = Result<Option<BlockRef>, SourceError>> + Send;

    /// The Billing Contract's logs of `events` in blocks `from..=to`, in chain order.
    fn logs(
        &self,
        from: u64,
        to: u64,
        events: EventSet,
    ) -> impl Future<Output = Result<Vec<ChainLog>, SourceError>> + Send;
}
