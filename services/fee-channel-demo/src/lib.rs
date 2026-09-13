//! A local, end-to-end demo of a fixed-rate epoch payment channel.
//!
//! Two roles run in one process against anvil:
//!
//! - the **collector** ([`collector`]), which issues nonces, admits paid requests, and settles
//!   on chain;
//! - the **RP** ([`rp`]), which holds no nonce state and signs one authorisation per request.
//!
//! [`flow::run`] wires them together: deploy, register, open, fund, work, refuse at capacity,
//! fund again, settle, close.
//!
//! [`harness::run`] does the same against the real flamingo verifier host, which speaks the
//! same protocol over its own API. See the README for the two commands it takes.

pub mod chain;
pub mod collector;
pub mod flamingo;
pub mod flow;
pub mod harness;
pub mod rp;

// Used by the demo binary, not the library itself.
use clap as _;

/// Wall-clock seconds since the Unix epoch.
///
/// Saturates at zero rather than panicking; a clock before 1970 is not a case this demo needs
/// to distinguish, and every caller would otherwise have to handle an impossible error.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Installs a tracing subscriber honouring `RUST_LOG`, defaulting to `info`.
///
/// # Errors
/// Returns an error if a subscriber is already installed.
pub fn init_tracing() -> eyre::Result<()> {
    use tracing_subscriber::{EnvFilter, fmt};

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init()
        .map_err(|e| eyre::eyre!("{e}"))
}
