//! Configuration types and CLI/environment parsing for the OPRF node.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use alloy::primitives::Address;
use clap::Parser;
use oprf_service::config::OprfNodeConfig;

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct WorldOprfNodeConfig {
    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_NODE_BIND_ADDR", default_value = "0.0.0.0:4321")]
    pub bind_addr: SocketAddr,

    /// Max wait time the node waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration

    )]
    pub max_wait_time_shutdown: Duration,

    /// The address of the AccountRegistry smart contract
    #[clap(long, env = "OPRF_NODE_ACCOUNT_REGISTRY_CONTRACT")]
    pub account_registry_contract: Address,

    /// The address of the CredentialSchemaIssuerRegistry smart contract
    #[clap(long, env = "OPRF_NODE_CREDENTIAL_ISSUER_REGISTRY_CONTRACT")]
    pub credential_issuer_registry_contract: Address,

    /// Path to the verification key used to verify the proof provided by the user during session initialization.
    #[clap(long, env = "OPRF_NODE_USER_PROOF_VERIFICATION_KEY_PATH")]
    pub user_verification_key_path: PathBuf,

    /// The maximum size of the merkle store.
    ///
    /// Will drop old merkle roots if this capacity is reached.
    #[clap(long, env = "OPRF_NODE_MERKLE_STORE_SIZE", default_value = "100")]
    pub max_merkle_store_size: usize,

    /// The maximum size of the issuer pubkey store.
    ///
    /// Will drop not used public keys if this capacity is reached.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_ISSUER_PUBKEY_STORE_SIZE",
        default_value = "10000"
    )]
    pub max_issuer_pubkey_store_size: usize,

    /// If an issuer public key is not used longer than this duration, the node will drop the public key.
    ///
    /// This will only get relevant though if `max_issuer_pubkey_store_size` is reached.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_ISSUER_PUBKEY_NOT_USED",
        default_value = "1d",
        value_parser = humantime::parse_duration

    )]
    pub max_issuer_pubkey_not_used: Duration,

    /// The maximum delta between the received current_time_stamp the node current_time_stamp
    #[clap(
        long,
        env = "OPRF_NODE_CURRENT_TIME_STAMP_MAX_DIFFERENCE",
        default_value = "5min",
        value_parser = humantime::parse_duration

    )]
    pub current_time_stamp_max_difference: Duration,

    /// Interval to cleanup the signature history
    #[clap(
        long,
        env = "OPRF_NODE_SIGNATURE_HISTORY_CLEANUP_INTERVAL",
        default_value = "10min",
        value_parser = humantime::parse_duration

    )]
    pub signature_history_cleanup_interval: Duration,

    /// The OPRF node config
    #[clap(flatten)]
    pub node_config: OprfNodeConfig,
}
