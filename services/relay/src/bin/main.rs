use clap::Parser;
use eyre::Result;
use futures_util::FutureExt as _;
use world_id_relay::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    run().boxed().await
}

async fn run() -> Result<()> {
    dotenvy::dotenv().ok();

    let _guard = telemetry_batteries::init();

    tracing::info!("starting world-id-relay");

    let cli = Cli::parse();
    let cli_run = cli.run().boxed();

    if let Err(e) = cli_run.await {
        tracing::error!(error = ?e, "relay terminated with error");
        std::process::exit(1);
    }

    Ok(())
}
