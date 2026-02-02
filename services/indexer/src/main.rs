use std::path::Path;
use world_id_indexer::{GlobalConfig, IndexerResult};

#[tokio::main]
async fn main() -> IndexerResult<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();

    tracing::info!("Starting world-id-indexer...");

    let config = GlobalConfig::from_env()?;
    world_id_indexer::run_indexer(config).await?;

    tracing::info!("⚠️ Exiting world-id-indexer...");
    Ok(())
}
