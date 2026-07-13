//! Configuration types and environment parsing for the OPRF accountant.

use std::{num::NonZeroUsize, time::Duration};

use alloy::primitives::Address;
use secrecy::SecretString;
use serde::Deserialize;
use taceo_nodes_common::{postgres::PostgresConfig, web3};

/// The configuration for the OPRF accountant service.
///
/// It can be configured via environment variables.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct OprfAccountantConfig {
    /// The postgres config
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,

    /// The address of the `BillingContract` smart contract
    pub billing_contract: Address,

    /// How often the accountant checks the `BillingContract` for an epoch to vote on.
    ///
    /// Needs to be smaller than the current era's `votingWindow`, or the accountant risks waking
    /// up after an epoch's voting window has already closed and missing the vote entirely.
    #[serde(
        default = "OprfAccountantConfig::default_tick_interval",
        with = "humantime_serde"
    )]
    pub tick_interval: Duration,

    /// The maximum time to wait for a `submitBillingVotes` transaction to be confirmed before
    /// giving up on voting for an epoch.
    ///
    /// Should be kept well below the current era's `votingWindow`: once the voting window opens,
    /// only whatever time remains until `votingWindowEnd` is available to submit the vote, so too
    /// large a timeout can let a vote attempt run past the window close instead of failing fast
    /// enough to retry.
    #[serde(
        default = "OprfAccountantConfig::default_vote_timeout",
        with = "humantime_serde"
    )]
    pub vote_timeout: Duration,

    /// A additional offset to be added to the start of the voting window.
    ///
    /// This is used to ensure that the OPRF nodes have enough time to send their requests
    /// to the accountant before the voting window starts.
    /// The offset should be at least be 2x the flush interval of the `AccountantBatcher`.
    pub voting_window_offset: Duration,

    /// The blockchain RPC config
    #[serde(rename = "rpc")]
    pub rpc_provider_config: web3::HttpRpcProviderConfig,

    // TODO split into 1 for the EIP-712 signature and 1 for the transaction signing.
    /// The private key used to sign billing vote chunks and to submit `submitBillingVotes`
    /// transactions.
    pub wallet_private_key: SecretString,

    /// The chunk size for billing votes to be submitted to the `BillingContract`.
    #[serde(default = "OprfAccountantConfig::default_billing_vote_chunk_size")]
    pub billing_vote_chunk_size: NonZeroUsize,
}

impl OprfAccountantConfig {
    /// Default billing vote chunk size
    fn default_billing_vote_chunk_size() -> NonZeroUsize {
        NonZeroUsize::new(128).expect("non-zero")
    }

    /// Default tick interval
    fn default_tick_interval() -> Duration {
        Duration::from_secs(60)
    }

    /// Default vote timeout
    fn default_vote_timeout() -> Duration {
        Duration::from_mins(5)
    }
}
