use std::path::Path;

use clap::Parser;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = dotenvy::from_path(Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"));
    let _guard = telemetry_batteries::init();

    let config = world_id_relay::config::Config::parse();

    tracing::info!("world-id-relay starting");

    if let Err(error) = world_id_relay::run(config).await {
        tracing::error!(error = ?error, "relay terminated with error");
        return Err(error);
    }

    Ok(())
}
