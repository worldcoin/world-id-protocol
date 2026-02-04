#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// When both http and axum features are enabled, axum is preferred for StatusCode.
// The http crate is unused in this case but kept as a dependency for compatibility.
#[cfg(all(feature = "axum", feature = "http-minimal"))]
use http as _;

mod types;
pub use types::*;
