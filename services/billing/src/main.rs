//! Binary entrypoint for the World ID billing service.

use clap::Parser;
use world_id_billing::cli::Cli;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = dotenvy::dotenv();

    let _guard = telemetry_batteries::init();
    world_id_billing::metrics::describe_metrics();

    Cli::parse().run().await
}
