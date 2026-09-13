//! Runs the fixed-rate fee-channel demo, or the local end-to-end harness.

#![allow(
    unused_crate_dependencies,
    reason = "the binary uses a subset of the crate's deps"
)]

use std::{path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use eyre::Result;
use world_id_fee_channel_demo::{
    flow::{self, FlowConfig},
    harness::{self, HarnessConfig},
    init_tracing,
};

/// Local demos of a World ID fixed-rate payment channel.
#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Runs the whole channel in one process, against a collector built from this crate.
    Demo(DemoArgs),
    /// Runs the channel against the real flamingo verifier host, started in another terminal.
    LocalE2e(LocalE2eArgs),
}

#[derive(Debug, Parser)]
struct DemoArgs {
    /// Units funded before the first batch of requests.
    #[arg(long, default_value_t = 4)]
    first_funding_units: u64,
    /// Units funded after the epoch runs out.
    #[arg(long, default_value_t = 2)]
    top_up_units: u64,
    /// Units funded and deliberately never spent.
    #[arg(long, default_value_t = 0)]
    unspent_units: u64,
    /// Price of one unit, in whole tokens.
    #[arg(long, default_value_t = 1)]
    price_tokens: u64,
    /// Epoch length in seconds.
    #[arg(long, default_value_t = 3_600)]
    epoch_length_secs: u64,
    /// Longest a signed payment may live, in seconds.
    #[arg(long, default_value_t = 600)]
    max_request_lifetime_secs: u64,
    /// Return each signature to the collector instead of presenting it for work.
    #[arg(long)]
    early_return: bool,
}

#[derive(Debug, Parser)]
struct LocalE2eArgs {
    /// The flamingo host's versioned API root.
    #[arg(long, default_value = "http://127.0.0.1:8000/v1")]
    collector_url: reqwest::Url,
    /// Units funded before the first batch, and again after the refusal.
    #[arg(long, default_value_t = 3)]
    units: u64,
    /// Price of one unit, in whole tokens.
    #[arg(long, default_value_t = 1)]
    price_tokens: u64,
    /// Epoch length in seconds.
    #[arg(long, default_value_t = 3_600)]
    epoch_length_secs: u64,
    /// Port anvil listens on.
    #[arg(long, default_value_t = 8545)]
    anvil_port: u16,
    /// Seconds to wait for the host to report ready.
    #[arg(long, default_value_t = 180)]
    ready_timeout_secs: u64,
    /// Where to write the env block the host needs.
    #[arg(long, default_value = "target/local-e2e.env")]
    env_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing()?;

    match args.command {
        Command::Demo(args) => run_demo(args).await,
        Command::LocalE2e(args) => run_local_e2e(args).await,
    }
}

async fn run_demo(args: DemoArgs) -> Result<()> {
    let report = flow::run(FlowConfig {
        first_funding_units: args.first_funding_units,
        top_up_units: args.top_up_units,
        unspent_units: args.unspent_units,
        price_tokens: args.price_tokens,
        epoch_length_secs: args.epoch_length_secs,
        max_request_lifetime_secs: args.max_request_lifetime_secs,
        early_return: args.early_return,
    })
    .await?;

    let rows: [(&str, String); 11] = [
        ("channel", report.channel_id.to_string()),
        ("epoch", report.epoch.to_string()),
        (
            "admitted before refusal",
            report.admitted_before_refusal.to_string(),
        ),
        ("refusal class", report.refusal_class.clone()),
        ("units proven by refusal", report.proven_units.to_string()),
        (
            "admitted after top-up",
            report.admitted_after_top_up.to_string(),
        ),
        ("settled units", report.settled_units.to_string()),
        ("lane high water", format!("{:?}", report.lane_high_water)),
        ("funded", report.funded.to_string()),
        ("collector balance", report.collector_balance.to_string()),
        ("escrow balance", report.escrow_balance.to_string()),
    ];

    println!();
    for (label, value) in rows {
        println!("{label:<26} {value}");
    }
    println!("{:<26} {}", "epoch closed", report.closed);
    Ok(())
}

async fn run_local_e2e(args: LocalE2eArgs) -> Result<()> {
    let report = harness::run(&HarnessConfig {
        units: args.units,
        price_tokens: args.price_tokens,
        epoch_length_secs: args.epoch_length_secs,
        collector_url: args.collector_url,
        anvil_port: args.anvil_port,
        ready_timeout: Duration::from_secs(args.ready_timeout_secs),
        env_path: args.env_path,
    })
    .await?;

    harness::print_summary(&report);
    Ok(())
}
