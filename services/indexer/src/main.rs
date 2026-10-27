#![recursion_limit = "256"]

use std::path::Path;

use futures_util::FutureExt as _;
use world_id_indexer::GlobalConfig;

use telemetry_batteries::TopLevelResultExt;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();
    world_id_indexer::metrics::describe_metrics();

    tracing::info!("Starting world-id-indexer...");

    let config = GlobalConfig::from_env()?;
    let indexer_run = unsafe { world_id_indexer::run_indexer(config) }.boxed();
    indexer_run.await.panic_on_top_level_error();

    tracing::info!("⚠️ Exiting world-id-indexer...");

    Ok(())
}
