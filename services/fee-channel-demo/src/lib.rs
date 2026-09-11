//! A local, end-to-end demo of a YABS fee channel.
//!
//! Three roles run in one process against anvil:
//!
//! - the **nonce manager** ([`nonce_manager`]), the spec's public nonce service, with a lease
//!   so two RP workers cannot be handed the same counter;
//! - the **collector** ([`collector`]), a mock work host that admits a request only if the
//!   channel can still pay for it, and settles on-chain in batches;
//! - the **RP** ([`rp`]), which leases a nonce, signs a `ProofRequestV2`, and asks for work.
//!
//! [`flow::run`] wires all three together: deploy, register, open, work, settle, close.

pub mod chain;
pub mod collector;
pub mod flow;
pub mod nonce_manager;
pub mod rp;

// Used by the demo binary and by JSON assertions in the tests, not the library itself.
use clap as _;
use serde_json as _;

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
