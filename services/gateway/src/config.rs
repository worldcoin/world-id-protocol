use std::net::SocketAddr;

use alloy::primitives::Address;
use clap::Parser;
use world_id_services_common::ProviderArgs;

use crate::error::{GatewayError, GatewayResult};

pub mod defaults {
    pub const MAX_CREATE_BATCH_SIZE: usize = 100;
    pub const MAX_OPS_BATCH_SIZE: usize = 10;
    pub const REQUEST_TIMEOUT_SECS: u64 = 10;
    pub const LISTEN_ADDR: &str = "0.0.0.0:8081";
    pub const SWEEPER_INTERVAL_SECS: u64 = 30;
    pub const STALE_QUEUED_THRESHOLD_SECS: u64 = 60;
    pub const STALE_SUBMITTED_THRESHOLD_SECS: u64 = 600;
    pub const WALLET_SIGN_LEASE_SECS: u64 = 30;
    pub const WALLET_STATE_TTL_SECS: u64 = 86_400;
    pub const WALLET_RELEASE_CONFIRMATIONS: u64 = 1;
    pub const WALLET_RESOLUTION_TIMEOUT_SECS: u64 = 900;
    pub const WALLET_TRACKER_INTERVAL_SECS: u64 = 2;
    pub const WALLET_FIRST_PROBE_DELAY_SECS: u64 = 2;
    /// Bounded wait for a free wallet. Kept well below
    /// `STALE_QUEUED_THRESHOLD_SECS` so a batch waiting on capacity cannot be
    /// mistaken for an abandoned request.
    pub const WALLET_ACQUIRE_TIMEOUT_SECS: u64 = 20;
    pub const WALLET_REBROADCAST_INTERVAL_SECS: u64 = 30;
    pub const WALLET_REBROADCAST_MAX_ATTEMPTS: u32 = 10;
    /// Slack added to the resolution timeout when deriving the in-flight lock
    /// lifetime, so a lock never lapses while its request is still being
    /// submitted.
    pub const WALLET_INFLIGHT_TTL_MARGIN_SECS: u64 = 60;
}

/// WorldIDRegistry implementation version to use for gateway request routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryVersion {
    V1,
    V2,
}

impl std::str::FromStr for RegistryVersion {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2),
            _ => Err(format!(
                "invalid registry version: {value}; expected v1 or v2"
            )),
        }
    }
}

/// Batching configuration for transaction submission.
#[derive(Clone, Debug)]
pub struct BatcherConfig {
    pub max_create_batch_size: usize,
    pub max_ops_batch_size: usize,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            max_create_batch_size: defaults::MAX_CREATE_BATCH_SIZE,
            max_ops_batch_size: defaults::MAX_OPS_BATCH_SIZE,
        }
    }
}

/// Rate limiting configuration for leaf_index-based requests.
///
/// Both fields are always present — the optionality is expressed at the
/// call-site via `Option<RateLimitConfig>`.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub window_secs: u64,
    pub max_requests: u64,
}

/// Configuration for the orphan sweeper background task.
#[derive(Clone, Debug)]
pub struct OrphanSweeperConfig {
    pub interval_secs: u64,
    pub stale_queued_threshold_secs: u64,
    pub stale_submitted_threshold_secs: u64,
}

impl Default for OrphanSweeperConfig {
    fn default() -> Self {
        Self {
            interval_secs: defaults::SWEEPER_INTERVAL_SECS,
            stale_queued_threshold_secs: defaults::STALE_QUEUED_THRESHOLD_SECS,
            stale_submitted_threshold_secs: defaults::STALE_SUBMITTED_THRESHOLD_SECS,
        }
    }
}

/// Configuration for durable wallet leasing and transaction resolution.
///
/// Every field is a bound on an operation that can fail: signing, waiting for a
/// free wallet, deciding a transaction's fate, and retrying a broadcast.
#[derive(Clone, Debug)]
pub struct WalletConfig {
    /// How long a wallet lease is held while its batch is signed. Bounds only
    /// the signing phase: nothing has been broadcast, so expiry is safe.
    pub sign_lease_secs: u64,
    /// Lifetime of a committed record. A rollback backstop, deliberately far
    /// longer than any resolution window.
    pub state_ttl_secs: u64,
    /// Confirmations required before a wallet is released, counting the
    /// inclusion block itself. `1` therefore means "included"; set it to the
    /// chain's practical reorg depth plus one to keep the
    /// one-transaction-per-wallet guarantee strict.
    pub release_confirmations: u64,
    /// How long a transaction may stay undecided before its wallet is parked.
    pub resolution_timeout_secs: u64,
    /// Resolver tick interval.
    pub tracker_interval_secs: u64,
    /// Delay before the resolver first probes a freshly committed record, so it
    /// does not race the submitter's own broadcast.
    pub first_probe_delay_secs: u64,
    /// Bounded wait for a free wallet before a batch is returned to the queue.
    pub acquire_timeout_secs: u64,
    /// Minimum spacing between re-broadcasts of the same transaction.
    pub rebroadcast_interval_secs: u64,
    /// Re-broadcast attempts before the resolver stops trying and lets the
    /// resolution timeout park the wallet.
    pub rebroadcast_max_attempts: u32,
    /// Wallets excluded from new work but still resolved.
    ///
    /// Draining is the way to remove a wallet from service: it keeps being
    /// resolved until its record clears, then silently stops being used. Simply
    /// dropping it from the pool would leave an in-flight transaction with no
    /// one responsible for it.
    pub draining_addresses: Vec<Address>,
}

impl WalletConfig {
    /// Lifetime of an in-flight lock, derived so it outlives the submission it
    /// protects rather than being a fixed value that can lapse early.
    #[must_use]
    pub const fn inflight_ttl_secs(&self) -> u64 {
        self.resolution_timeout_secs + defaults::WALLET_INFLIGHT_TTL_MARGIN_SECS
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            sign_lease_secs: defaults::WALLET_SIGN_LEASE_SECS,
            state_ttl_secs: defaults::WALLET_STATE_TTL_SECS,
            release_confirmations: defaults::WALLET_RELEASE_CONFIRMATIONS,
            resolution_timeout_secs: defaults::WALLET_RESOLUTION_TIMEOUT_SECS,
            tracker_interval_secs: defaults::WALLET_TRACKER_INTERVAL_SECS,
            first_probe_delay_secs: defaults::WALLET_FIRST_PROBE_DELAY_SECS,
            acquire_timeout_secs: defaults::WALLET_ACQUIRE_TIMEOUT_SECS,
            rebroadcast_interval_secs: defaults::WALLET_REBROADCAST_INTERVAL_SECS,
            rebroadcast_max_attempts: defaults::WALLET_REBROADCAST_MAX_ATTEMPTS,
            draining_addresses: Vec::new(),
        }
    }
}

/// Durable wallet submission knobs.
#[derive(Clone, Debug, clap::Args)]
pub struct WalletArgs {
    /// How long a wallet lease is held while its batch is signed, in seconds.
    #[arg(long, env = "WALLET_SIGN_LEASE_SECS", default_value_t = defaults::WALLET_SIGN_LEASE_SECS)]
    pub sign_lease_secs: u64,

    /// Lifetime of a committed wallet record, in seconds.
    #[arg(long, env = "WALLET_STATE_TTL_SECS", default_value_t = defaults::WALLET_STATE_TTL_SECS)]
    pub state_ttl_secs: u64,

    /// Confirmations required before a wallet is reused.
    #[arg(long, env = "WALLET_RELEASE_CONFIRMATIONS", default_value_t = defaults::WALLET_RELEASE_CONFIRMATIONS)]
    pub release_confirmations: u64,

    /// How long a transaction may stay undecided before its wallet is parked, in seconds.
    #[arg(long, env = "WALLET_RESOLUTION_TIMEOUT_SECS", default_value_t = defaults::WALLET_RESOLUTION_TIMEOUT_SECS)]
    pub resolution_timeout_secs: u64,

    /// Resolver tick interval, in seconds.
    #[arg(long, env = "WALLET_TRACKER_INTERVAL_SECS", default_value_t = defaults::WALLET_TRACKER_INTERVAL_SECS)]
    pub tracker_interval_secs: u64,

    /// Delay before the resolver first probes a freshly committed transaction, in seconds.
    #[arg(long, env = "WALLET_FIRST_PROBE_DELAY_SECS", default_value_t = defaults::WALLET_FIRST_PROBE_DELAY_SECS)]
    pub first_probe_delay_secs: u64,

    /// Bounded wait for a free wallet before returning a batch to the queue, in seconds.
    #[arg(long, env = "WALLET_ACQUIRE_TIMEOUT_SECS", default_value_t = defaults::WALLET_ACQUIRE_TIMEOUT_SECS)]
    pub acquire_timeout_secs: u64,

    /// Minimum spacing between re-broadcasts of the same transaction, in seconds.
    #[arg(long, env = "WALLET_REBROADCAST_INTERVAL_SECS", default_value_t = defaults::WALLET_REBROADCAST_INTERVAL_SECS)]
    pub rebroadcast_interval_secs: u64,

    /// Re-broadcast attempts before a wallet is left for the resolution timeout to park.
    #[arg(long, env = "WALLET_REBROADCAST_MAX_ATTEMPTS", default_value_t = defaults::WALLET_REBROADCAST_MAX_ATTEMPTS)]
    pub rebroadcast_max_attempts: u32,

    /// Comma-separated wallet addresses to drain.
    ///
    /// A draining wallet is excluded from new work but still resolved, so a
    /// wallet can be retired without abandoning a transaction it signed.
    #[arg(long, env = "WALLET_DRAINING_ADDRESSES")]
    pub draining_addresses: Option<String>,
}

impl Default for WalletArgs {
    fn default() -> Self {
        Self {
            sign_lease_secs: defaults::WALLET_SIGN_LEASE_SECS,
            state_ttl_secs: defaults::WALLET_STATE_TTL_SECS,
            release_confirmations: defaults::WALLET_RELEASE_CONFIRMATIONS,
            resolution_timeout_secs: defaults::WALLET_RESOLUTION_TIMEOUT_SECS,
            tracker_interval_secs: defaults::WALLET_TRACKER_INTERVAL_SECS,
            first_probe_delay_secs: defaults::WALLET_FIRST_PROBE_DELAY_SECS,
            acquire_timeout_secs: defaults::WALLET_ACQUIRE_TIMEOUT_SECS,
            rebroadcast_interval_secs: defaults::WALLET_REBROADCAST_INTERVAL_SECS,
            rebroadcast_max_attempts: defaults::WALLET_REBROADCAST_MAX_ATTEMPTS,
            draining_addresses: None,
        }
    }
}

/// Policy-driven batching configuration.
#[derive(Clone, Debug, clap::Args)]
pub struct BatchPolicyConfig {
    /// Re-evaluation cadence for policy decisions, in milliseconds.
    #[arg(long, env = "BATCH_REEVAL_MS", default_value = "1000")]
    pub reeval_ms: u64,

    /// Hard max wait for queued requests before forcing send, in seconds.
    #[arg(long, env = "BATCH_MAX_WAIT_SECS", default_value = "30")]
    pub max_wait_secs: u64,

    /// EMA alpha for base fee smoothing in [0, 1].
    #[arg(long, env = "BATCH_COST_EMA_ALPHA", default_value = "0.2")]
    pub cost_ema_alpha: f64,

    /// Cost pressure threshold: cost_score >= threshold is considered expensive.
    #[arg(long, env = "BATCH_COST_HIGH_RATIO", default_value = "1.2")]
    pub cost_high_ratio: f64,

    /// Backlog size where urgency size pressure reaches 1.0.
    #[arg(long, env = "BATCH_BACKLOG_HIGH_WATERMARK", default_value = "200")]
    pub backlog_high_watermark: usize,
}

impl Default for BatchPolicyConfig {
    fn default() -> Self {
        Self {
            reeval_ms: 1_000,
            max_wait_secs: 30,
            cost_ema_alpha: 0.2,
            cost_high_ratio: 1.2,
            backlog_high_watermark: 200,
        }
    }
}

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct GatewayConfig {
    /// The address of the `WorldIDRegistry` contract
    #[arg(long, env = "REGISTRY_ADDRESS")]
    pub registry_addr: Address,

    /// Registry implementation version to use for request routing.
    #[arg(long, env = "REGISTRY_VERSION")]
    pub registry_version: RegistryVersion,

    /// The HTTP RPC endpoint to submit transactions
    #[command(flatten)]
    pub provider: ProviderArgs,

    /// Maximum batch size for create account requests
    #[arg(long, env = "MAX_CREATE_BATCH_SIZE", default_value_t = defaults::MAX_CREATE_BATCH_SIZE)]
    pub max_create_batch_size: usize,

    /// Maximum batch size for ops (insert/update/remove/recover) requests
    #[arg(long, env = "MAX_OPS_BATCH_SIZE", default_value_t = defaults::MAX_OPS_BATCH_SIZE)]
    pub max_ops_batch_size: usize,

    /// HTTP request timeout in seconds
    #[arg(long, env = "REQUEST_TIMEOUT_SECS", default_value_t = defaults::REQUEST_TIMEOUT_SECS)]
    pub request_timeout_secs: u64,

    /// The address and port to listen for HTTP requests
    #[arg(long, env = "LISTEN_ADDR", default_value = defaults::LISTEN_ADDR)]
    pub listen_addr: SocketAddr,

    /// Redis URL for request storage (e.g. redis://localhost:6379)
    #[arg(long, env = "REDIS_URL")]
    pub redis_url: String,

    /// Rate limit window in seconds (sliding window). Requires --rate-limit-max-requests.
    #[arg(
        long = "rate-limit-window-secs",
        env = "RATE_LIMIT_WINDOW_SECS",
        requires = "rate_limit_max_requests"
    )]
    pub rate_limit_window_secs: Option<u64>,

    /// Maximum requests per leaf_index within the rate limit window. Requires --rate-limit-window-secs.
    #[arg(
        long = "rate-limit-max-requests",
        env = "RATE_LIMIT_MAX_REQUESTS",
        requires = "rate_limit_window_secs"
    )]
    pub rate_limit_max_requests: Option<u64>,

    /// How often the orphan sweeper runs, in seconds.
    #[arg(long, env = "ORPHAN_SWEEPER_INTERVAL_SECS", default_value_t = defaults::SWEEPER_INTERVAL_SECS)]
    pub sweeper_interval_secs: u64,

    #[command(flatten)]
    pub wallet: WalletArgs,

    #[command(flatten)]
    pub batch_policy: BatchPolicyConfig,

    /// Staleness threshold for Queued/Batching requests (seconds).
    #[arg(long, env = "STALE_QUEUED_THRESHOLD_SECS", default_value_t = defaults::STALE_QUEUED_THRESHOLD_SECS)]
    pub stale_queued_threshold_secs: u64,

    /// Staleness threshold for Submitted requests with no receipt (seconds).
    #[arg(long, env = "STALE_SUBMITTED_THRESHOLD_SECS", default_value_t = defaults::STALE_SUBMITTED_THRESHOLD_SECS)]
    pub stale_submitted_threshold_secs: u64,
}

impl GatewayConfig {
    pub fn from_env() -> GatewayResult<Self> {
        let config = Self::parse();
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> GatewayResult<()> {
        if self.provider.signer.is_pool_signer() && self.provider.signer.has_legacy_signer() {
            return Err(GatewayError::Config(
                "a shared wallet pool (WALLET_PRIVATE_KEYS or AWS_KMS_WALLET_KEYS) must not be \
                 combined with a per-replica signer variable"
                    .to_string(),
            ));
        }

        if self.provider.signer.signer_config().is_none() {
            return Err(GatewayError::Config(
                "exactly one of --wallet-private-key, --aws-kms-key-id, or \
                 --aws-kms-key-ids must be provided"
                    .to_string(),
            ));
        }

        if self.listen_addr.port() != 8080 {
            tracing::warn!(
                "Gateway is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)"
            );
        }

        if !(0.0..=1.0).contains(&self.batch_policy.cost_ema_alpha) {
            return Err(GatewayError::Config(
                "BATCH_COST_EMA_ALPHA must be in the inclusive range [0, 1]".to_string(),
            ));
        }

        if self.batch_policy.reeval_ms == 0 {
            return Err(GatewayError::Config(
                "BATCH_REEVAL_MS must be greater than 0".to_string(),
            ));
        }

        if self.batch_policy.max_wait_secs == 0 {
            return Err(GatewayError::Config(
                "BATCH_MAX_WAIT_SECS must be greater than 0".to_string(),
            ));
        }

        let max_wait_ms = (self.batch_policy.max_wait_secs as u128) * 1000;
        if (self.batch_policy.reeval_ms as u128) > max_wait_ms {
            return Err(GatewayError::Config(
                "BATCH_REEVAL_MS must be less than or equal to BATCH_MAX_WAIT_SECS * 1000"
                    .to_string(),
            ));
        }

        if !self.batch_policy.cost_high_ratio.is_finite() {
            return Err(GatewayError::Config(
                "BATCH_COST_HIGH_RATIO must be a finite number".to_string(),
            ));
        }

        if self.batch_policy.cost_high_ratio <= 0.0 {
            return Err(GatewayError::Config(
                "BATCH_COST_HIGH_RATIO must be greater than 0".to_string(),
            ));
        }

        if self.batch_policy.backlog_high_watermark == 0 {
            return Err(GatewayError::Config(
                "BATCH_BACKLOG_HIGH_WATERMARK must be greater than 0".to_string(),
            ));
        }

        if self.sweeper().stale_queued_threshold_secs <= self.batch_policy.max_wait_secs {
            return Err(GatewayError::Config(
                "STALE_QUEUED_THRESHOLD_SECS must be greater than BATCH_MAX_WAIT_SECS".to_string(),
            ));
        }

        self.validate_wallet()?;

        Ok(())
    }

    /// Check the durable wallet knobs against their documented bounds.
    fn validate_wallet(&self) -> GatewayResult<()> {
        let wallet = self.wallet()?;

        if wallet.sign_lease_secs < 5 {
            return Err(GatewayError::Config(
                "WALLET_SIGN_LEASE_SECS must be at least 5".to_string(),
            ));
        }

        if wallet.state_ttl_secs <= wallet.resolution_timeout_secs {
            return Err(GatewayError::Config(
                "WALLET_STATE_TTL_SECS must be greater than WALLET_RESOLUTION_TIMEOUT_SECS"
                    .to_string(),
            ));
        }

        if wallet.release_confirmations == 0 {
            return Err(GatewayError::Config(
                "WALLET_RELEASE_CONFIRMATIONS must be at least 1".to_string(),
            ));
        }

        if wallet.resolution_timeout_secs < 60 {
            return Err(GatewayError::Config(
                "WALLET_RESOLUTION_TIMEOUT_SECS must be at least 60".to_string(),
            ));
        }

        if wallet.tracker_interval_secs == 0 {
            return Err(GatewayError::Config(
                "WALLET_TRACKER_INTERVAL_SECS must be greater than 0".to_string(),
            ));
        }

        if wallet.first_probe_delay_secs < wallet.tracker_interval_secs {
            return Err(GatewayError::Config(
                "WALLET_FIRST_PROBE_DELAY_SECS must be at least WALLET_TRACKER_INTERVAL_SECS"
                    .to_string(),
            ));
        }

        if wallet.acquire_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "WALLET_ACQUIRE_TIMEOUT_SECS must be greater than 0".to_string(),
            ));
        }

        if wallet.acquire_timeout_secs >= self.stale_queued_threshold_secs {
            return Err(GatewayError::Config(
                "WALLET_ACQUIRE_TIMEOUT_SECS must be less than STALE_QUEUED_THRESHOLD_SECS"
                    .to_string(),
            ));
        }

        if wallet.rebroadcast_interval_secs < wallet.tracker_interval_secs {
            return Err(GatewayError::Config(
                "WALLET_REBROADCAST_INTERVAL_SECS must be at least WALLET_TRACKER_INTERVAL_SECS"
                    .to_string(),
            ));
        }

        if wallet.rebroadcast_max_attempts == 0 {
            return Err(GatewayError::Config(
                "WALLET_REBROADCAST_MAX_ATTEMPTS must be at least 1".to_string(),
            ));
        }

        Ok(())
    }

    pub fn batcher(&self) -> BatcherConfig {
        BatcherConfig {
            max_create_batch_size: self.max_create_batch_size,
            max_ops_batch_size: self.max_ops_batch_size,
        }
    }

    pub fn rate_limit(&self) -> Option<RateLimitConfig> {
        match (self.rate_limit_window_secs, self.rate_limit_max_requests) {
            (Some(window_secs), Some(max_requests)) => Some(RateLimitConfig {
                window_secs,
                max_requests,
            }),
            _ => None,
        }
    }

    pub fn sweeper(&self) -> OrphanSweeperConfig {
        OrphanSweeperConfig {
            interval_secs: self.sweeper_interval_secs,
            stale_queued_threshold_secs: self.stale_queued_threshold_secs,
            stale_submitted_threshold_secs: self.stale_submitted_threshold_secs,
        }
    }

    /// Durable wallet submission configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when `WALLET_DRAINING_ADDRESSES` is not a
    /// comma-separated list of addresses.
    pub fn wallet(&self) -> GatewayResult<WalletConfig> {
        let draining_addresses = match &self.wallet.draining_addresses {
            None => Vec::new(),
            Some(raw) => raw
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(|entry| {
                    entry.parse::<Address>().map_err(|_| {
                        GatewayError::Config(format!(
                            "WALLET_DRAINING_ADDRESSES contains an invalid address: {entry}"
                        ))
                    })
                })
                .collect::<GatewayResult<Vec<Address>>>()?,
        };

        Ok(WalletConfig {
            sign_lease_secs: self.wallet.sign_lease_secs,
            state_ttl_secs: self.wallet.state_ttl_secs,
            release_confirmations: self.wallet.release_confirmations,
            resolution_timeout_secs: self.wallet.resolution_timeout_secs,
            tracker_interval_secs: self.wallet.tracker_interval_secs,
            first_probe_delay_secs: self.wallet.first_probe_delay_secs,
            acquire_timeout_secs: self.wallet.acquire_timeout_secs,
            rebroadcast_interval_secs: self.wallet.rebroadcast_interval_secs,
            rebroadcast_max_attempts: self.wallet.rebroadcast_max_attempts,
            draining_addresses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    /// Default Anvil test private key (account 0). This is a well-known
    /// development key, not a real secret.
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    const BASE_ARGS: &[&str] = &[
        "test",
        "--registry-addr",
        "0x0000000000000000000000000000000000000001",
        "--registry-version",
        "v1",
        "--rpc-url",
        "http://localhost:8545",
        "--redis-url",
        "redis://localhost:6379",
    ];

    fn parse_with_signer_args(signer_args: &[&str]) -> Result<GatewayConfig, clap::Error> {
        let args: Vec<&str> = BASE_ARGS
            .iter()
            .chain(signer_args.iter())
            .copied()
            .collect();
        GatewayConfig::try_parse_from(args)
    }

    fn parse_valid_config() -> GatewayConfig {
        parse_with_signer_args(&["--wallet-private-key", TEST_PRIVATE_KEY])
            .expect("valid config should parse")
    }

    #[test]
    fn registry_version_parses_v2() {
        let config = GatewayConfig::try_parse_from([
            "test",
            "--registry-addr",
            "0x0000000000000000000000000000000000000001",
            "--registry-version",
            "v2",
            "--rpc-url",
            "http://localhost:8545",
            "--redis-url",
            "redis://localhost:6379",
            "--wallet-private-key",
            TEST_PRIVATE_KEY,
        ])
        .expect("valid config should parse");
        assert_eq!(config.registry_version, RegistryVersion::V2);
    }

    #[test]
    fn registry_version_is_required() {
        let result = GatewayConfig::try_parse_from([
            "test",
            "--registry-addr",
            "0x0000000000000000000000000000000000000001",
            "--rpc-url",
            "http://localhost:8545",
            "--redis-url",
            "redis://localhost:6379",
            "--wallet-private-key",
            TEST_PRIVATE_KEY,
        ]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn test_both_options_fails() {
        let result = parse_with_signer_args(&[
            "--wallet-private-key",
            "0xdeadbeef",
            "--aws-kms-key-id",
            "my-key-id",
        ]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_neither_option_fails_validation() {
        let config = parse_with_signer_args(&[]).expect("clap parsing should succeed");
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("wallet-private-key") || err.contains("aws-kms-key-id"),
            "error should mention signer options: {err}"
        );
    }

    #[test]
    fn rate_limit_disabled_when_omitted() {
        let config = parse_with_signer_args(&[]).expect("clap parsing should succeed");
        assert!(config.rate_limit().is_none());
    }

    #[test]
    fn rate_limit_enabled_when_both_provided() {
        let config = parse_with_signer_args(&[
            "--rate-limit-window-secs",
            "60",
            "--rate-limit-max-requests",
            "100",
        ])
        .expect("clap parsing should succeed");
        let rl = config.rate_limit().expect("rate_limit should be Some");
        assert_eq!(rl.window_secs, 60);
        assert_eq!(rl.max_requests, 100);
    }

    #[test]
    fn rate_limit_rejects_only_window() {
        let result = parse_with_signer_args(&["--rate-limit-window-secs", "60"]);
        assert!(result.is_err(), "providing only window_secs should fail");
    }

    #[test]
    fn rate_limit_rejects_only_max_requests() {
        let result = parse_with_signer_args(&["--rate-limit-max-requests", "100"]);
        assert!(result.is_err(), "providing only max_requests should fail");
    }

    #[test]
    fn test_reeval_ms_must_not_exceed_max_wait_ms() {
        let mut config = parse_valid_config();
        config.batch_policy.max_wait_secs = 30;
        config.batch_policy.reeval_ms = 31_000;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("BATCH_REEVAL_MS"));
    }

    #[test]
    fn test_cost_high_ratio_must_be_finite() {
        let mut config = parse_valid_config();
        config.batch_policy.cost_high_ratio = f64::NAN;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("BATCH_COST_HIGH_RATIO"));
        assert!(err.contains("finite"));
    }

    #[test]
    fn test_stale_queued_threshold_must_exceed_max_wait_secs() {
        let mut config = parse_valid_config();
        config.batch_policy.max_wait_secs = 30;
        config.stale_queued_threshold_secs = 30;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("STALE_QUEUED_THRESHOLD_SECS"));
    }
}
