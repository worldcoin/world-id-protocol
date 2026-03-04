use clap::Parser;
use eyre::Result;

use world_id_relay::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let env_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();

    tracing::info!("starting world-id-relay");

    let cli = Cli::parse();

    if let Err(e) = cli.run().await {
        tracing::error!(error = ?e, "relay terminated with error");
        std::process::exit(1);
    }

    Ok(())
}
