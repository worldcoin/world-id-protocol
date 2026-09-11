//! The demo scenario, asserted end to end.

#![allow(
    unused_crate_dependencies,
    reason = "the test uses a subset of the crate's deps"
)]

use alloy::primitives::U256;
use world_id_fee_channel_demo::flow::{self, FlowConfig};

/// One WLD, in wei.
fn wld(n: u64) -> U256 {
    U256::from(n) * U256::from(1_000_000_000_000_000_000u128)
}

/// 18 requests against a 14 WLD deposit: the channel funds 14 and refuses the rest.
#[tokio::test(flavor = "multi_thread")]
async fn channel_pays_for_what_it_can_afford() -> eyre::Result<()> {
    // A threshold far above the request count keeps the schedule in its linear region, so the
    // fee is a flat 1 WLD per verification and the arithmetic below stays readable.
    let report = flow::run(FlowConfig {
        requests_per_worker: 6,
        deposit_wld: 14,
        threshold: 1000,
        ..FlowConfig::default()
    })
    .await?;

    assert_eq!(report.admitted, 14, "the deposit funds exactly 14 units");
    assert_eq!(report.rejected_insolvent, 4);
    assert_eq!(
        report.rejected_other, 0,
        "no request may fail for any reason other than funding"
    );
    for reason in &report.rejection_reasons {
        assert!(
            reason.contains("owe"),
            "every refusal must be an insolvency: {reason}"
        );
    }

    assert_eq!(report.collector_wld, wld(14));
    assert_eq!(report.settled_count, U256::from(14u64));
    assert_eq!(
        report.lane_high_water.iter().sum::<u64>(),
        14,
        "the escrow charges on the sum of lane high-water marks"
    );
    assert!(
        report.settlements >= 3,
        "two automatic settlements at 5 and 10, plus the final sweep, got {}",
        report.settlements
    );

    // Rejected requests still burned a nonce: the RP signs before the collector decides, and
    // the counter is what the escrow bills on. Gaps are paid for.
    assert_eq!(
        report.manager_lane_counters.iter().sum::<u64>(),
        18,
        "all 18 requests consumed a nonce, including the 4 that were refused"
    );
    assert_eq!(report.manager_lane_counters.len(), 3);
    assert_eq!(
        report.manager_latest_verified, 3,
        "every lane's stored request must verify against the spend key"
    );

    assert_eq!(report.refund, U256::ZERO, "the deposit was spent exactly");
    assert_eq!(report.escrow_wld_after_close, U256::ZERO);
    assert_eq!(
        report.payer_wld_after_close,
        U256::ZERO,
        "the payer deposited 14 and got nothing back"
    );
    Ok(())
}

/// A deposit with room to spare: everything is admitted and the rest comes back.
#[tokio::test(flavor = "multi_thread")]
async fn all_requests_fit_and_payer_is_refunded() -> eyre::Result<()> {
    let report = flow::run(FlowConfig {
        lane_count: 2,
        workers: 2,
        requests_per_worker: 4,
        deposit_wld: 20,
        threshold: 1000,
        ..FlowConfig::default()
    })
    .await?;

    assert_eq!(report.admitted, 8);
    assert_eq!(report.rejected_insolvent, 0);
    assert_eq!(report.rejected_other, 0);
    assert_eq!(report.collector_wld, wld(8));
    assert_eq!(report.settled_count, U256::from(8u64));
    assert_eq!(report.refund, wld(12));
    assert_eq!(report.payer_wld_after_close, wld(12));
    assert_eq!(report.escrow_wld_after_close, U256::ZERO);
    assert_eq!(report.manager_lane_counters.iter().sum::<u64>(), 8);
    assert_eq!(report.manager_latest_verified, 2);
    Ok(())
}

/// Past the threshold the marginal price decays, so a channel funded to the schedule's ceiling
/// keeps admitting work indefinitely and still costs less than the cap.
#[tokio::test(flavor = "multi_thread")]
async fn rational_decay_never_runs_dry_and_caps_the_month() -> eyre::Result<()> {
    let report = flow::run(FlowConfig {
        lane_count: 3,
        workers: 3,
        requests_per_worker: 10,
        deposit_wld: 8,
        price_wld: 1,
        threshold: 4,
        ..FlowConfig::default()
    })
    .await?;

    assert_eq!(report.admitted, 30, "every request is affordable");
    assert_eq!(report.rejected_insolvent, 0);
    assert_eq!(report.rejected_other, 0);
    assert_eq!(report.settled_count, U256::from(30u64));

    let expected = U256::from(7_466_666_666_666_666_666u128);
    assert_eq!(report.collector_wld, expected);
    assert_eq!(report.cumulative_fee_at_end, expected);
    assert_eq!(report.max_fee, wld(8), "2 * price * threshold");
    assert!(
        report.collector_wld < report.max_fee,
        "the total stays under the cap however much work is done"
    );

    assert_eq!(report.refund, U256::from(533_333_333_333_333_334u128));
    assert_eq!(report.refund, wld(8) - report.collector_wld);
    assert_eq!(report.escrow_wld_after_close, U256::ZERO);

    // The marginal price never rises by more than a wei, and the first verification past the
    // threshold already costs 0.8 WLD instead of 1. The one wei of slack is not cosmetic:
    // floor division makes the marginal genuinely non-monotonic far out on the tail.
    let curve = &report.cumulative_fee_curve;
    assert_eq!(curve.len(), 31, "cumulativeFee(0..=30)");
    assert_eq!(
        curve[5] - curve[4],
        U256::from(800_000_000_000_000_000u128),
        "first post-threshold marginal"
    );
    let mut previous_marginal: Option<U256> = None;
    for k in 4..30usize {
        let marginal = curve[k + 1] - curve[k];
        if let Some(previous) = previous_marginal {
            assert!(
                marginal <= previous + U256::from(1u64),
                "marginal price rose by more than a wei at k={k}: {marginal} > {previous}"
            );
        }
        previous_marginal = Some(marginal);
    }
    Ok(())
}
