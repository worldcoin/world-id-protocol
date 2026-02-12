use std::path::Path;
use world_id_indexer::GlobalConfig;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();

    tracing::info!("Starting world-id-indexer...");

    let config = GlobalConfig::from_env()?;
    if let Err(error) = unsafe { world_id_indexer::run_indexer(config).await } {
        tracing::error!(error = ?error, "indexer terminated with error");
        return Err(error);
    }

    tracing::info!("⚠️ Exiting world-id-indexer...");

    Ok(())
}
