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
    let cfg = FlowConfig::default();
    let report = flow::run(cfg).await?;

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
