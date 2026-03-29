#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use clap as _;
use dotenvy as _;
use rustls as _;
use telemetry_batteries as _;
use tracing_subscriber as _;

pub mod abi_decoder;
pub mod app;
pub mod config;
pub mod metrics;
pub mod subscription;
pub mod util;

pub use app::run;

#[cfg(test)]
mod tests;
