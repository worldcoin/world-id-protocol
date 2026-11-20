//! A local HTTP service that verifies WIP-202 Proofs of Embedding Similarity for an RP, so
//! services not written in Rust can use `world-id-rp` without building it.
//!
//! The sidecar is stateless: the caller keeps each [`ProofRequest`] it issued, sends it with the
//! proof, and consumes the request's `nonce` once a proof is accepted. See the README.
//!
//! [`ProofRequest`]: world_id_primitives::ProofRequest
#![recursion_limit = "256"]

use std::path::Path;

use clap::Parser as _;
use telemetry_batteries::TopLevelResultExt as _;

use crate::config::Config;

mod config;
mod error;
mod metrics;
mod policy;
mod registries;
mod routes;
mod server;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();
    metrics::describe_metrics();

    server::run(Config::parse())
        .await
        .panic_on_top_level_error();

    Ok(())
}
