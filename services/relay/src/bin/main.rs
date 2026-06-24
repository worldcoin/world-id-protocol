use clap::Parser;
use eyre::Result;
use futures_util::FutureExt as _;
use world_id_relay::cli::Cli;

use telemetry_batteries::TopLevelResultExt;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let _guard = telemetry_batteries::init();
    world_id_relay::metrics::describe_metrics();

    tracing::info!("starting world-id-relay");

    let cli = Cli::parse();
    let cli_run = cli.run().boxed();

    cli_run.await.panic_on_top_level_error();

    Ok(())
}
