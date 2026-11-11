//! The follower against a real node: backfill, live blocks and a reorganization on anvil.
//!
//! The Billing Contract's events come from `BillingEventEmitter`, which emits them with the same
//! signatures, so the test needs no registration proofs.
// An integration test links every dependency of the crate but uses only some.
#![allow(unused_crate_dependencies)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::{
    network::EthereumWallet,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
};
use eyre::{Result, eyre};
use world_id_billing_follower::{BillingFollower, BillingUpdate, FollowerConfig};
use world_id_primitives::{
    FieldElement,
    billing::{BillingState, period_start},
    rp::RpId,
};
use world_id_test_utils::anvil::{TestAnvil, world_id_billing::BillingEventEmitter};

const ANVIL_CHAIN_ID: u64 = 31_337;
const RP: u64 = 7;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after the epoch")
        .as_secs()
}

/// A copy of the state built only from the follower's updates.
#[derive(Default)]
struct Mirror {
    state: BillingState,
    head: u64,
    backfill_done: bool,
}

impl Mirror {
    fn apply(&mut self, update: BillingUpdate) {
        if update.reset {
            self.state = BillingState::default();
        }
        for op in update.ops {
            self.state.apply(op).expect("ops apply to the copy");
        }
        self.head = update.head;
        self.backfill_done = update.backfill_done;
    }

    /// Applies updates until the copy is current up to `block`.
    async fn sync_to(&mut self, follower: &mut BillingFollower, block: u64) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !(self.backfill_done && self.head >= block) {
                self.apply(follower.next().await?);
            }
            Ok::<_, eyre::Report>(())
        })
        .await
        .map_err(|_| eyre!("the follower did not reach block {block}"))?
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follows_backfill_live_blocks_and_a_reorganization() -> Result<()> {
    let anvil = TestAnvil::spawn_auto_mine()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(anvil.signer(0)?))
        .connect_http(anvil.endpoint().parse()?);
    let emitter = BillingEventEmitter::deploy(&provider).await?;
    let deploy_block = provider.get_block_number().await?;
    let period = period_start(now())?;
    let rp = RpId::new(RP);
    let nullifier = |value: u64| FieldElement::from(value);

    let send = |call: alloy::rpc::types::TransactionRequest| {
        let provider = provider.clone();
        async move {
            let receipt = provider.send_transaction(call).await?.get_receipt().await?;
            eyre::ensure!(receipt.status(), "the emitter call reverted");
            Ok::<_, eyre::Report>(receipt.block_number.unwrap_or_default())
        }
    };
    send(emitter.billedRpUpdated(RP, true).into_transaction_request()).await?;
    let backfilled = send(
        emitter
            .registered(RP, period, U256::from(1))
            .into_transaction_request(),
    )
    .await?;

    let config = FollowerConfig {
        reorg_window: 8,
        block_time: Duration::from_millis(500),
        poll_interval: Duration::from_millis(50),
        stalled_poll_interval: Duration::from_millis(200),
        ..FollowerConfig::new(ANVIL_CHAIN_ID, *emitter.address(), deploy_block)
    };
    let mut follower =
        BillingFollower::connect(vec![anvil.endpoint().parse()?], config.clone()).await?;
    let mut mirror = Mirror::default();
    mirror.sync_to(&mut follower, backfilled).await?;
    assert!(mirror.state.is_billed(rp));
    assert!(mirror.state.is_registered(nullifier(1), rp, now()));

    // A live block, then a reorganization that replaces it.
    let snapshot: U256 = provider.raw_request("evm_snapshot".into(), ()).await?;
    let orphaned = send(
        emitter
            .registered(RP, period, U256::from(2))
            .into_transaction_request(),
    )
    .await?;
    mirror.sync_to(&mut follower, orphaned).await?;
    assert!(mirror.state.is_registered(nullifier(2), rp, now()));

    let reverted: bool = provider
        .raw_request("evm_revert".into(), (snapshot,))
        .await?;
    assert!(reverted);
    // Mine past the orphaned block, so the new fork is longer.
    let _: String = provider.raw_request("evm_mine".into(), ()).await?;
    let replacing = send(
        emitter
            .registered(RP, period, U256::from(3))
            .into_transaction_request(),
    )
    .await?;
    mirror.sync_to(&mut follower, replacing).await?;
    assert!(!mirror.state.is_registered(nullifier(2), rp, now()));
    assert!(mirror.state.is_registered(nullifier(3), rp, now()));
    assert!(mirror.state.is_registered(nullifier(1), rp, now()));

    // A follower started now sees the same state.
    let mut fresh = BillingFollower::connect(vec![anvil.endpoint().parse()?], config).await?;
    let mut fresh_mirror = Mirror::default();
    fresh_mirror.sync_to(&mut fresh, replacing).await?;
    assert_eq!(fresh_mirror.state, mirror.state);
    assert_eq!(fresh.state(), follower.state());

    Ok(())
}
