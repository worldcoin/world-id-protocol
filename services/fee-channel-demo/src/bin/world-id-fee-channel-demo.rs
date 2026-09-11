//! Runs the YABS fee-channel demo against a throwaway anvil instance.

#![allow(
    unused_crate_dependencies,
    reason = "the binary uses a subset of the crate's deps"
)]

use clap::Parser;
use eyre::Result;
use world_id_fee_channel_demo::{
    flow::{self, FlowConfig},
    init_tracing,
};

/// Local end-to-end demo of a World ID fee channel.
#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Independent nonce lanes on the channel.
    #[arg(long, default_value_t = 3)]
    lane_count: u32,
    /// Concurrent RP workers.
    #[arg(long, default_value_t = 3)]
    workers: usize,
    /// Requests each worker issues.
    #[arg(long, default_value_t = 10)]
    requests_per_worker: usize,
    /// WLD the payer escrows.
    #[arg(long, default_value_t = 8)]
    deposit_wld: u64,
    /// WLD charged per verification before the decay begins.
    #[arg(long, default_value_t = 1)]
    price_wld: u64,
    /// Verifications priced at the flat marginal rate; past this the fee decays.
    #[arg(long, default_value_t = 4)]
    threshold: u64,
    /// Admissions between automatic settlements.
    #[arg(long, default_value_t = 5)]
    settle_every: usize,
    /// Seconds the collector has to settle.
    #[arg(long, default_value_t = 600)]
    collection_window_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing()?;

    let report = flow::run(FlowConfig {
        lane_count: args.lane_count,
        workers: args.workers,
        requests_per_worker: args.requests_per_worker,
        deposit_wld: args.deposit_wld,
        price_wld: args.price_wld,
        threshold: args.threshold,
        settle_every: args.settle_every,
        collection_window_secs: args.collection_window_secs,
    })
    .await?;

    let lane_high_water = format!("{:?}", report.lane_high_water);
    let manager_counters = format!("{:?}", report.manager_lane_counters);
    let rows: [(&str, String); 14] = [
        ("channel", report.channel_id.to_string()),
        ("admitted", report.admitted.to_string()),
        (
            "rejected (insolvent)",
            report.rejected_insolvent.to_string(),
        ),
        ("rejected (other)", report.rejected_other.to_string()),
        ("settlements", report.settlements.to_string()),
        ("settled count", report.settled_count.to_string()),
        ("lane high water", lane_high_water),
        ("manager counters", manager_counters),
        ("collector WLD", report.collector_wld.to_string()),
        ("cumulative fee", report.cumulative_fee_at_end.to_string()),
        ("max fee (cap)", report.max_fee.to_string()),
        ("refund to payer", report.refund.to_string()),
        ("payer WLD", report.payer_wld_after_close.to_string()),
        ("escrow WLD", report.escrow_wld_after_close.to_string()),
    ];

    println!();
    for (label, value) in rows {
        println!("{label:<22} {value}");
    }
    Ok(())
}
