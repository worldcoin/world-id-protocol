use clap::Parser;
use eyre::Result;
use tracing::{error, info};

use world_id_relay::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let env_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);

    let _guard = tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .init();

    info!("starting world-id-relay");

    let cli = Cli::parse();

    if let Err(e) = cli.run().await {
        error!("error running relay: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}
