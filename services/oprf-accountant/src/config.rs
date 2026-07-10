//! Configuration types and environment parsing for the OPRF accountant.

use std::time::Duration;

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

    /// The interval in which to check if we can submit votes to the `BillingContract`.
    ///
    /// Must less than the `votingWindow` the contract is configured with,
    /// otherwise the accountant may miss an epoch's voting window entirely.
    #[serde(
        default = "OprfAccountantConfig::default_submit_interval",
        with = "humantime_serde"
    )]
    pub tick_interval: Duration,

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
}

impl OprfAccountantConfig {
    /// Default submit interval
    fn default_submit_interval() -> Duration {
        Duration::from_secs(30)
    }
}
