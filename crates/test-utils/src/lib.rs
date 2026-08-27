#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod anvil;
pub mod fixtures;
pub mod merkle;
pub mod stubs;

pub use taceo_nodes_common::test_utils::shared_postgres_testcontainer;

use testcontainers_modules::{
    redis::{REDIS_PORT, Redis},
    testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
};

/// Starts an isolated Redis instance for a test and returns its connection URL.
///
/// Keep the returned container alive for as long as the test uses the URL.
pub async fn redis_testcontainer() -> eyre::Result<(ContainerAsync<Redis>, String)> {
    let container = Redis::default().with_tag("latest").start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await?;
    Ok((container, format!("redis://{host}:{port}")))
}
