#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// Suppress warning when both http and axum are enabled (axum is preferred)
#[cfg(all(feature = "axum", feature = "http-minimal"))]
use http as _;

mod types;
pub use types::*;
