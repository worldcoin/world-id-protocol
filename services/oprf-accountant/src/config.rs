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
}
