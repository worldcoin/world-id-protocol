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

    /// The `BillingContract` submit interval.
    ///
    /// Must be at most half the smallest `votingWindow` (and `epochLength`) the contract is
    /// configured with, otherwise the accountant may miss an epoch's voting window entirely.
    #[serde(
        default = "OprfAccountantConfig::default_submit_interval",
        with = "humantime_serde"
    )]
    pub submit_interval: Duration,

    /// A additional offset to be added to the start of the voting window.
    ///
    /// This is used to ensure that the OPRF nodes have enough time to send their requests
    /// to the accountant before the voting window starts.
    /// The offset should be ~2x the flush interval of the `AccountantBatcher`.
    pub voting_window_offset: Duration,

    /// The blockchain RPC config
    #[serde(rename = "rpc")]
    pub rpc_provider_config: web3::HttpRpcProviderConfig,

    /// The blockchain RPC URL for the websocket connection.
    pub ws_rpc_url: SecretString,

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
