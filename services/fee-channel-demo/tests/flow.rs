//! The demo scenario, asserted end to end.

#![allow(
    unused_crate_dependencies,
    reason = "the test uses a subset of the crate's deps"
)]

use alloy::primitives::U256;
use world_id_fee_channel_demo::{
    flow::{self, FlowConfig},
    init_tracing,
};

/// `n` whole tokens, in wei.
fn tokens(n: u64) -> U256 {
    U256::from(n) * U256::from(1_000_000_000_000_000_000u128)
}

/// The whole lifecycle: funded capacity is spent exactly, the next request is refused with a
/// proof, a top-up lifts the cap, and closing pays the collector everything that was funded.
#[tokio::test(flavor = "multi_thread")]
async fn capacity_is_bought_spent_proven_and_closed() -> eyre::Result<()> {
    // Only the first test to run installs a subscriber; the rest share it.
    let _ = init_tracing();
    let report = flow::run(FlowConfig {
        first_funding_units: 4,
        top_up_units: 2,
        ..FlowConfig::default()
    })
    .await?;

    assert_eq!(
        report.admitted_before_refusal, 4,
        "the first funding buys exactly four units"
    );
    assert_eq!(
        report.refusal_class, "capacity_exhausted",
        "the fifth request must fail for want of funding, not for any other reason"
    );
    assert_eq!(
        report.proven_units, 4,
        "the refusal proof accounts for every unit the collector claims"
    );
    assert_eq!(report.admitted_after_top_up, 2, "a top-up lifts the cap");

    assert_eq!(report.stats.admitted, 6);
    assert_eq!(report.stats.refused_other, 0);

    assert_eq!(
        report.settled_units, 6,
        "the escrow counts the units the collector admitted"
    );
    assert_eq!(
        report.lane_high_water.iter().sum::<u64>(),
        6,
        "settled units are the sum of the lane marks"
    );

    assert_eq!(report.funded, tokens(6));
    assert!(
        report.closed,
        "an empty batch after the epoch ends closes it"
    );
    assert_eq!(
        report.collector_balance,
        tokens(6),
        "once closed, paid equals funded"
    );
    assert_eq!(
        report.escrow_balance,
        U256::ZERO,
        "no path returns tokens to a funder"
    );
    Ok(())
}

/// Returning the signature early books the unit and frees the lane at once, so a serial
/// workload uses one lane and the whole epoch settles with a single signature.
#[tokio::test(flavor = "multi_thread")]
async fn early_return_keeps_the_epoch_to_one_lane() -> eyre::Result<()> {
    let _ = init_tracing();
    let report = flow::run(FlowConfig {
        first_funding_units: 3,
        top_up_units: 1,
        early_return: true,
        ..FlowConfig::default()
    })
    .await?;

    assert_eq!(report.admitted_before_refusal, 3);
    assert_eq!(report.admitted_after_top_up, 1);
    assert_eq!(
        report.lane_high_water,
        vec![4],
        "one lane, counter four: four units proved by one signature"
    );
    assert_eq!(report.settled_units, 4);
    assert_eq!(report.collector_balance, tokens(4));
    assert!(report.closed);
    Ok(())
}

/// Unused capacity is never refunded: the closing settlement pays it to the collector.
#[tokio::test(flavor = "multi_thread")]
async fn unused_capacity_is_paid_to_the_collector_at_close() -> eyre::Result<()> {
    let _ = init_tracing();
    let report = flow::run(FlowConfig {
        first_funding_units: 2,
        top_up_units: 1,
        unspent_units: 3,
        ..FlowConfig::default()
    })
    .await?;

    assert_eq!(report.settled_units, 3, "only three units were ever signed");
    assert_eq!(report.funded, tokens(6), "six were funded");
    assert_eq!(
        report.collector_balance, report.funded,
        "once closed, paid equals funded however little was used"
    );
    assert_eq!(
        report.escrow_balance,
        U256::ZERO,
        "no path returns tokens to a funder"
    );
    Ok(())
}
