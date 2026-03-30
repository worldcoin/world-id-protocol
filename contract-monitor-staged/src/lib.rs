#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use axum as _;
use clap as _;
use dotenvy as _;
use rustls as _;
use telemetry_batteries as _;
use tracing_subscriber as _;

pub mod abi_decoder;
pub mod app;
pub mod config;
pub mod health;
pub mod metrics;
pub mod subscription;

pub use app::run;

#[cfg(test)]
mod tests;
