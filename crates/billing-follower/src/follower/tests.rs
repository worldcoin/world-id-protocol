use alloy::primitives::{Address, U256};
use world_id_primitives::{billing::BillingState, rp::RpId};

use super::*;
use crate::testing::{CHAIN_ID, FakeChain};

const DAY: u64 = 86_400;
// 1 Oct and 1 Nov 2026, 00:00:00 AoE.
const OCT_2026: u64 = 1_790_856_000;
const NOV_2026: u64 = 1_793_534_400;

/// The follower's clock: 10 November 2026, inside November's period only.
const fn now() -> u64 {
    NOV_2026 + 10 * DAY
}

fn registered(nullifier: u64, rp_id: u64) -> BillingEvent {
    registered_in(nullifier, rp_id, NOV_2026)
}

fn registered_in(nullifier: u64, rp_id: u64, period_start: u64) -> BillingEvent {
    BillingEvent::Registered {
        rp_id: RpId::new(rp_id),
        period_start,
        nullifier: U256::from(nullifier),
    }
}

const fn billed(rp_id: u64, billed: bool) -> BillingEvent {
    BillingEvent::BilledRpUpdated {
        rp_id: RpId::new(rp_id),
        billed,
    }
}

fn config(reorg_window: usize) -> FollowerConfig {
    FollowerConfig {
        max_log_range: 3,
        reorg_window,
        ..FollowerConfig::new(CHAIN_ID, Address::ZERO, 0)
    }
}

async fn follower(chain: &FakeChain, config: FollowerConfig) -> BillingFollower<FakeChain> {
    let mut follower = BillingFollower::with_source(chain.clone(), config)
        .await
        .unwrap();
    follower.clock = now;
    follower
}

/// A consumer's copy of the state, built only from updates.
#[derive(Default)]
struct Mirror {
    state: BillingState,
    resets: usize,
    head: u64,
    backfill_done: bool,
}

impl Mirror {
    fn apply(&mut self, update: BillingUpdate) {
        if update.reset {
            self.state = BillingState::default();
            self.resets += 1;
        }
        for op in update.ops {
            assert!(
                self.state.apply(op).unwrap().is_some(),
                "every op changes the state: {op:?}"
            );
        }
        self.head = update.head;
        self.backfill_done = update.backfill_done;
    }

    /// Applies updates until the copy is current with the chain's head.
    async fn sync(&mut self, follower: &mut BillingFollower<FakeChain>, chain: &FakeChain) {
        while !(self.backfill_done && self.head == chain.head().number) {
            self.apply(follower.next().await.unwrap());
        }
    }

    fn assert_matches(&self, follower: &BillingFollower<FakeChain>) {
        let mut rebuilt = BillingState::default();
        for op in follower.state().snapshot() {
            rebuilt.apply(op).unwrap();
        }
        assert_eq!(self.state, rebuilt);
    }
}

fn nullifier(value: u64) -> FieldElement {
    FieldElement::from(value)
}

#[tokio::test(start_paused = true)]
async fn backfills_then_follows_new_blocks() {
    let chain = FakeChain::new(NOV_2026 + DAY);
    chain.mine(vec![billed(7, true)]);
    chain.mine_empty(5);
    chain.mine(vec![registered(1, 7), registered(2, 8)]);
    chain.mine_empty(10);
    chain.mine(vec![billed(8, true), billed(7, false)]);
    chain.mine_empty(3);

    let mut follower = follower(&chain, config(4)).await;
    let mut mirror = Mirror::default();
    mirror.sync(&mut follower, &chain).await;
    mirror.assert_matches(&follower);
    assert!(!follower.state().is_billed(RpId::new(7)));
    assert!(follower.state().is_billed(RpId::new(8)));
    assert!(
        follower
            .state()
            .is_registered(nullifier(1), RpId::new(7), now())
    );

    // Once caught up, every new block is reported, with or without changes.
    chain.mine(vec![registered(3, 8)]);
    let update = follower.next().await.unwrap();
    assert_eq!(update.head, chain.head().number);
    assert!(update.backfill_done);
    assert_eq!(update.ops.len(), 1);
    mirror.apply(update);

    chain.mine_empty(1);
    let update = follower.next().await.unwrap();
    assert_eq!(update.head, chain.head().number);
    assert!(update.ops.is_empty());
    mirror.apply(update);
    mirror.assert_matches(&follower);
}

#[tokio::test(start_paused = true)]
async fn reads_registrations_only_from_the_active_periods() {
    let chain = FakeChain::new(OCT_2026);
    chain.mine_at(
        OCT_2026 + DAY,
        vec![billed(7, true), registered_in(1, 7, OCT_2026)],
    );
    chain.mine_at(OCT_2026 + 2 * DAY, Vec::new());
    // Registered during November's overlap, for November.
    chain.mine_at(NOV_2026 - DAY, vec![registered(2, 7)]);
    chain.mine_at(NOV_2026 + DAY, vec![registered(3, 7)]);
    chain.mine_empty(6);

    let mut follower = follower(&chain, config(2)).await;
    let mut mirror = Mirror::default();
    mirror.sync(&mut follower, &chain).await;
    mirror.assert_matches(&follower);

    let state = follower.state();
    assert!(state.is_billed(RpId::new(7)));
    assert_eq!(state.registration(nullifier(1)), None);
    assert!(state.is_registered(nullifier(2), RpId::new(7), now()));
    assert!(state.is_registered(nullifier(3), RpId::new(7), now()));
    // October's blocks were read for BilledRpUpdated only.
    let calls = chain.log_calls();
    assert!(
        calls
            .iter()
            .filter(|(from, _, _)| *from < 3)
            .all(|(_, to, events)| *to < 3 && *events == EventSet::BilledRps),
        "{calls:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn undoes_a_reorganization_within_the_window() {
    for depth in [1, 3] {
        let chain = FakeChain::new(NOV_2026 + DAY);
        chain.mine(vec![billed(7, true)]);
        chain.mine_empty(4);
        chain.mine(vec![registered(1, 7), billed(8, true)]);
        chain.mine(vec![registered(2, 7)]);
        chain.mine(vec![billed(7, false)]);

        let mut follower = follower(&chain, config(5)).await;
        let mut mirror = Mirror::default();
        mirror.sync(&mut follower, &chain).await;

        chain.reorg(depth);
        chain.mine(vec![registered(9, 7)]);
        chain.mine_empty(depth);
        mirror.sync(&mut follower, &chain).await;
        mirror.assert_matches(&follower);

        let state = follower.state();
        assert!(state.is_registered(nullifier(9), RpId::new(7), now()));
        // The undone blocks' changes are gone; the earlier ones remain.
        assert!(state.is_billed(RpId::new(7)));
        assert_eq!(state.registration(nullifier(2)).is_some(), depth < 2);
        assert_eq!(state.registration(nullifier(1)).is_some(), depth < 3);
        assert_eq!(state.is_billed(RpId::new(8)), depth < 3);
        assert_eq!(mirror.resets, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn starts_over_after_a_fork_deeper_than_the_window() {
    let chain = FakeChain::new(NOV_2026 + DAY);
    chain.mine(vec![billed(7, true)]);
    chain.mine(vec![registered(1, 7)]);
    chain.mine_empty(4);

    let mut follower = follower(&chain, config(2)).await;
    let mut mirror = Mirror::default();
    mirror.sync(&mut follower, &chain).await;

    chain.reorg(6);
    chain.mine(vec![registered(2, 8)]);
    chain.mine_empty(6);
    mirror.sync(&mut follower, &chain).await;
    mirror.assert_matches(&follower);

    assert_eq!(mirror.resets, 1);
    let state = follower.state();
    assert!(!state.is_billed(RpId::new(7)));
    assert_eq!(state.registration(nullifier(1)), None);
    assert!(state.is_registered(nullifier(2), RpId::new(8), now()));
}

#[tokio::test(start_paused = true)]
async fn retries_failed_reads() {
    let chain = FakeChain::new(NOV_2026 + DAY);
    chain.mine(vec![billed(7, true), registered(1, 7)]);
    chain.mine_empty(8);
    chain.fail("eth_getBlockByNumber", 2);
    chain.fail("eth_getLogs", 3);

    let mut follower = follower(&chain, config(3)).await;
    let mut mirror = Mirror::default();
    mirror.sync(&mut follower, &chain).await;
    mirror.assert_matches(&follower);
    assert!(
        follower
            .state()
            .is_registered(nullifier(1), RpId::new(7), now())
    );
}

#[tokio::test(start_paused = true)]
async fn shrinks_log_ranges_the_source_rejects() {
    let chain = FakeChain::new(NOV_2026 + DAY);
    chain.mine(vec![billed(7, true)]);
    chain.mine_empty(20);
    chain.mine(vec![registered(1, 7)]);
    chain.mine_empty(20);
    chain.limit_log_range(2);

    let config = FollowerConfig {
        max_log_range: 16,
        ..config(4)
    };
    let mut follower = follower(&chain, config).await;
    let mut mirror = Mirror::default();
    mirror.sync(&mut follower, &chain).await;
    mirror.assert_matches(&follower);
    assert!(
        follower
            .state()
            .is_registered(nullifier(1), RpId::new(7), now())
    );
}

#[tokio::test(start_paused = true)]
async fn skips_a_nullifier_outside_the_field() {
    let chain = FakeChain::new(NOV_2026 + DAY);
    chain.mine(vec![
        BillingEvent::Registered {
            rp_id: RpId::new(7),
            period_start: NOV_2026,
            nullifier: U256::MAX,
        },
        registered(1, 7),
    ]);
    let mut follower = follower(&chain, config(4)).await;
    let mut mirror = Mirror::default();
    mirror.sync(&mut follower, &chain).await;
    assert_eq!(follower.state().registration_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn stops_on_a_nullifier_registered_twice() {
    let chain = FakeChain::new(NOV_2026 + DAY);
    chain.mine(vec![registered(1, 7), registered(1, 8)]);
    let mut follower = follower(&chain, config(4)).await;
    let error = loop {
        match follower.next().await {
            Ok(_) => {}
            Err(error) => break error,
        }
    };
    assert!(matches!(
        error,
        FollowerError::State(BillingStateError::Conflict)
    ));
}

#[tokio::test(start_paused = true)]
async fn rejects_another_chain() {
    let chain = FakeChain::new(NOV_2026);
    let config = FollowerConfig::new(CHAIN_ID + 1, Address::ZERO, 0);
    let Err(error) = BillingFollower::with_source(chain, config).await else {
        panic!("another chain must be rejected");
    };
    assert!(matches!(
        error,
        FollowerError::WrongChain {
            actual: CHAIN_ID,
            ..
        }
    ));
}
