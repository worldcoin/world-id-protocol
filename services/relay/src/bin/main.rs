use clap::Parser;
use eyre::Result;
use futures_util::FutureExt as _;
use world_id_relay::cli::Cli;

use telemetry_batteries::{LogFormat, TelemetryConfig, TelemetryPreset, TopLevelResultExt};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let mut telemetry_config = TelemetryConfig::from_env()?;
    if telemetry_config.preset == TelemetryPreset::Local && telemetry_config.log_format.is_none() {
        telemetry_config.log_format = Some(LogFormat::Json);
    }
    let _guard = telemetry_batteries::init_with_config(telemetry_config)?;
    world_id_relay::metrics::describe_metrics();

    tracing::info!("starting world-id-relay");

    let cli = Cli::parse();
    let cli_run = cli.run().boxed();

    cli_run.await.panic_on_top_level_error();

    Ok(())
}
