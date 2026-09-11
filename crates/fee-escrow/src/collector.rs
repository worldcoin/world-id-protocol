//! Collector-side admission: verify a request, then check the channel can still pay for it.

use std::collections::{BTreeMap, HashMap};

use alloy::sol_types::Eip712Domain;
use alloy_primitives::{B256, U256};

use crate::{
    request::{OnchainPaymentAuthorization, ProofRequestV2, RequestV2Error},
    typed_data::ChannelSettings,
};

/// Reasons a collector refuses to do work for a request.
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    /// The request itself is malformed or not signed by the channel's `spendKey`.
    #[error(transparent)]
    Request(#[from] RequestV2Error),
    /// The request's RP is not the RP the channel pays for.
    #[error("request rp id {found} does not match channel rp id {expected}")]
    RpIdMismatch {
        /// `ChannelSettings.rpId`.
        expected: u64,
        /// `inner.rp_id` on the request.
        found: u64,
    },
    /// The counter is at or below what this lane has already spent.
    #[error("lane {lane} counter {counter} is not above the high-water mark {high_water}")]
    StaleNonce {
        /// Lane the request targets.
        lane: u32,
        /// Counter the request carries.
        counter: u64,
        /// Highest counter already admitted on that lane.
        high_water: u64,
    },
    /// Admitting this request would owe more than the channel holds.
    #[error("channel would owe {owed} but only holds {balance}")]
    Insolvent {
        /// Fee owed after admitting the request.
        owed: U256,
        /// Tokens currently escrowed.
        balance: U256,
    },
    /// The request targets a different channel than the supplied view.
    #[error("request targets channel {requested} but the view describes {view}")]
    UnknownChannel {
        /// `channel_id` on the request.
        requested: B256,
        /// `channel_id` of the view passed to [`Ledger::admit`].
        view: B256,
    },
}

/// Snapshot of on-chain channel state, as returned by `getChannel`.
///
/// Holding `channel_id` alongside the settings lets [`Ledger::admit`] reject a request aimed at
/// a different channel without recomputing the id from chain id and escrow address.
#[derive(Debug, Clone)]
pub struct ChannelView {
    /// `computeChannelId(settings)`.
    pub channel_id: B256,
    /// Immutable channel terms.
    pub settings: ChannelSettings,
    /// Tokens currently escrowed.
    pub balance: U256,
    /// Tokens already paid to the collector.
    pub paid: U256,
    /// Σ over lanes of the highest settled counter.
    pub settled_count: U256,
}

/// Per-lane admission state.
#[derive(Debug, Clone, Default)]
struct LaneState {
    /// Highest counter admitted, settled or not.
    high_water: u64,
    /// Highest authorisation not yet known to be on chain.
    pending: Option<OnchainPaymentAuthorization>,
}

/// Per-channel admission state.
#[derive(Debug, Clone, Default)]
struct ChannelState {
    lanes: BTreeMap<u32, LaneState>,
}

impl ChannelState {
    /// Σ over lanes of the highest admitted counter, with `lane` overridden by `counter`.
    fn total_with(&self, lane: u32, counter: u64) -> U256 {
        let mut total = U256::from(counter);
        for (id, state) in &self.lanes {
            if *id != lane {
                total += U256::from(state.high_water);
            }
        }
        total
    }
}

/// The collector's off-chain view of what each channel owes it.
///
/// Tracks the highest counter admitted per lane, which is exactly what the escrow charges on:
/// `cumulativeFee(Σ lane high-water marks) - paid`. Only the highest pending authorisation per
/// lane ever needs submitting, so [`Self::settlement_batch`] returns at most `laneCount` entries.
///
/// In-memory and single-process. A real collector needs this to be durable and serialised per
/// channel, or two concurrent admissions can both pass the solvency check and overdraw.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    channels: HashMap<B256, ChannelState>,
}

impl Ledger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decides whether to perform the work this request pays for, and books it if so.
    ///
    /// `fee` must mirror the channel's `IFeeSchedule.cumulativeFee`. On success the request's
    /// authorisation becomes the lane's pending entry for the next [`Self::settlement_batch`].
    ///
    /// # Errors
    /// See [`AdmitError`]. Nothing is recorded when an error is returned.
    pub fn admit(
        &mut self,
        req: &ProofRequestV2,
        view: &ChannelView,
        fee: &dyn Fn(U256) -> U256,
        domain: &Eip712Domain,
    ) -> Result<(), AdmitError> {
        req.verify(domain, view.settings.spendKey)?;

        let (channel_id, nonce) = req
            .payment()?
            .ok_or(AdmitError::Request(RequestV2Error::NoPayment))?;
        if channel_id != view.channel_id {
            return Err(AdmitError::UnknownChannel {
                requested: channel_id,
                view: view.channel_id,
            });
        }

        let found = req.inner.rp_id.into_inner();
        if found != view.settings.rpId {
            return Err(AdmitError::RpIdMismatch {
                expected: view.settings.rpId,
                found,
            });
        }
        nonce
            .validate(view.settings.laneCount)
            .map_err(RequestV2Error::from)?;

        let high_water = self.high_water(channel_id, nonce.lane);
        if nonce.counter <= high_water {
            return Err(AdmitError::StaleNonce {
                lane: nonce.lane,
                counter: nonce.counter,
                high_water,
            });
        }

        let new_total =
            self.projected_total(channel_id, nonce.lane, nonce.counter, view.settled_count);
        let owed = fee(new_total).saturating_sub(view.paid);
        if owed > view.balance {
            return Err(AdmitError::Insolvent {
                owed,
                balance: view.balance,
            });
        }

        let auth = req.to_onchain_auth()?;
        let lane = self
            .channels
            .entry(channel_id)
            .or_default()
            .lanes
            .entry(nonce.lane)
            .or_default();
        lane.high_water = nonce.counter;
        lane.pending = Some(auth);
        Ok(())
    }

    /// The count [`Self::admit`] would price if `lane` advanced to `counter`.
    ///
    /// The escrow charges on Σ lane high-water marks, so this is that sum with `lane`
    /// overridden. It is clamped to `settled_count` so a ledger that has lost state cannot
    /// under-quote a channel someone else has already settled.
    ///
    /// Callers that price the fee out of band (an on-chain `IFeeSchedule` read, say) need this
    /// to compute the same argument `admit` will pass to its `fee` closure.
    #[must_use]
    pub fn projected_total(
        &self,
        channel_id: B256,
        lane: u32,
        counter: u64,
        settled_count: U256,
    ) -> U256 {
        self.channels
            .get(&channel_id)
            .map_or_else(|| U256::from(counter), |c| c.total_with(lane, counter))
            .max(settled_count)
    }

    /// Highest counter admitted on `lane`, or zero if the lane is untouched.
    #[must_use]
    pub fn high_water(&self, channel_id: B256, lane: u32) -> u64 {
        self.channels
            .get(&channel_id)
            .and_then(|c| c.lanes.get(&lane))
            .map_or(0, |lane| lane.high_water)
    }

    /// Channels holding at least one authorisation that has not been settled yet.
    #[must_use]
    pub fn channels_with_pending(&self) -> Vec<B256> {
        let mut ids: Vec<B256> = self
            .channels
            .iter()
            .filter(|(_, c)| c.lanes.values().any(|lane| lane.pending.is_some()))
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// The authorisations to pass to `settle`: the highest pending one per lane, lane-ordered.
    #[must_use]
    pub fn settlement_batch(&self, channel_id: B256) -> Vec<OnchainPaymentAuthorization> {
        self.channels
            .get(&channel_id)
            .map(|c| c.lanes.values().filter_map(|l| l.pending.clone()).collect())
            .unwrap_or_default()
    }

    /// Clears pending authorisations after a successful `settle`, keeping the high-water marks.
    pub fn mark_settled(&mut self, channel_id: B256) {
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            for lane in channel.lanes.values_mut() {
                lane.pending = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        nonce::LaneNonce,
        request::tests::{CHAIN_ID, ESCROW, signed, signer, test_domain},
        typed_data::channel_id,
    };
    use alloy_primitives::{U256, address, b256};

    const RP_ID: u64 = 7;
    /// One token per verification. These unit tests price the flat region of the schedule.
    const PRICE: u64 = 1_000_000_000_000_000_000;

    fn fee(count: U256) -> U256 {
        count * U256::from(PRICE)
    }

    fn view(spend_key: alloy_primitives::Address, balance: u64) -> ChannelView {
        let settings = ChannelSettings {
            rpId: RP_ID,
            payer: address!("0x1111111111111111111111111111111111111111"),
            spendKey: spend_key,
            collector: address!("0x3333333333333333333333333333333333333333"),
            token: address!("0x4444444444444444444444444444444444444444"),
            feeSchedule: address!("0x5555555555555555555555555555555555555555"),
            laneCount: 2,
            collectionDeadline: 1_800_000_000,
            salt: b256!("0x00000000000000000000000000000000000000000000000000000000000000ff"),
        };
        ChannelView {
            channel_id: channel_id(CHAIN_ID, ESCROW, &settings),
            settings,
            balance: U256::from(balance) * U256::from(PRICE),
            paid: U256::ZERO,
            settled_count: U256::ZERO,
        }
    }

    #[test]
    fn admits_then_rejects_a_replayed_nonce() {
        let key = signer(1);
        let view = view(key.address(), 10);
        let mut ledger = Ledger::new();

        let req = signed(&key, view.channel_id, LaneNonce::new(0, 1), RP_ID, 1);
        ledger
            .admit(&req, &view, &fee, &test_domain())
            .expect("first admission");

        let err = ledger
            .admit(&req, &view, &fee, &test_domain())
            .expect_err("replay must be refused");
        assert!(matches!(
            err,
            AdmitError::StaleNonce {
                lane: 0,
                counter: 1,
                high_water: 1
            }
        ));
    }

    #[test]
    fn rejects_a_lower_counter_on_the_same_lane() {
        let key = signer(1);
        let view = view(key.address(), 10);
        let mut ledger = Ledger::new();

        let high = signed(&key, view.channel_id, LaneNonce::new(0, 5), RP_ID, 1);
        ledger
            .admit(&high, &view, &fee, &test_domain())
            .expect("ok");

        let low = signed(&key, view.channel_id, LaneNonce::new(0, 4), RP_ID, 2);
        assert!(matches!(
            ledger.admit(&low, &view, &fee, &test_domain()),
            Err(AdmitError::StaleNonce { .. })
        ));
    }

    #[test]
    fn rejects_a_foreign_rp() {
        let key = signer(1);
        let view = view(key.address(), 10);
        let mut ledger = Ledger::new();

        let req = signed(&key, view.channel_id, LaneNonce::new(0, 1), RP_ID + 1, 1);
        assert!(matches!(
            ledger.admit(&req, &view, &fee, &test_domain()),
            Err(AdmitError::RpIdMismatch {
                expected: RP_ID,
                found: 8
            })
        ));
    }

    #[test]
    fn rejects_a_request_for_another_channel() {
        let key = signer(1);
        let view = view(key.address(), 10);
        let mut ledger = Ledger::new();

        let req = signed(&key, B256::ZERO, LaneNonce::new(0, 1), RP_ID, 1);
        assert!(matches!(
            ledger.admit(&req, &view, &fee, &test_domain()),
            Err(AdmitError::UnknownChannel { .. })
        ));
    }

    #[test]
    fn rejects_an_out_of_range_lane() {
        let key = signer(1);
        let view = view(key.address(), 10);
        let mut ledger = Ledger::new();

        let req = signed(&key, view.channel_id, LaneNonce::new(2, 1), RP_ID, 1);
        assert!(matches!(
            ledger.admit(&req, &view, &fee, &test_domain()),
            Err(AdmitError::Request(RequestV2Error::Nonce(_)))
        ));
    }

    #[test]
    fn rejects_once_the_channel_cannot_cover_the_fee() {
        let key = signer(1);
        let view = view(key.address(), 3);
        let mut ledger = Ledger::new();

        for counter in 1..=3u64 {
            let req = signed(
                &key,
                view.channel_id,
                LaneNonce::new(0, counter),
                RP_ID,
                counter,
            );
            ledger
                .admit(&req, &view, &fee, &test_domain())
                .unwrap_or_else(|e| panic!("admission {counter} must pass: {e}"));
        }

        let req = signed(&key, view.channel_id, LaneNonce::new(0, 4), RP_ID, 4);
        let err = ledger
            .admit(&req, &view, &fee, &test_domain())
            .expect_err("fourth must be refused");
        assert!(matches!(err, AdmitError::Insolvent { .. }));
        assert_eq!(
            ledger.high_water(view.channel_id, 0),
            3,
            "a refused request must not move the high-water mark"
        );
    }

    #[test]
    fn insolvency_accounts_across_lanes() {
        let key = signer(1);
        let view = view(key.address(), 2);
        let mut ledger = Ledger::new();

        for lane in 0..2u32 {
            let req = signed(
                &key,
                view.channel_id,
                LaneNonce::new(lane, 1),
                RP_ID,
                u64::from(lane),
            );
            ledger.admit(&req, &view, &fee, &test_domain()).expect("ok");
        }

        let third = signed(&key, view.channel_id, LaneNonce::new(1, 2), RP_ID, 9);
        assert!(matches!(
            ledger.admit(&third, &view, &fee, &test_domain()),
            Err(AdmitError::Insolvent { .. })
        ));
    }

    /// The value `admit` passes to its `fee` closure must be exactly what `projected_total`
    /// predicts, or a collector that prices the fee out of band quotes the wrong amount.
    #[test]
    fn projected_total_matches_what_admit_prices() {
        use std::cell::RefCell;

        let key = signer(1);
        let view = view(key.address(), 10);
        let mut ledger = Ledger::new();

        for (lane, counter) in [(0u32, 1u64), (1, 1), (0, 2), (1, 2), (0, 3)] {
            let predicted =
                ledger.projected_total(view.channel_id, lane, counter, view.settled_count);
            let seen = RefCell::new(None);
            let req = signed(
                &key,
                view.channel_id,
                LaneNonce::new(lane, counter),
                RP_ID,
                u64::from(lane) * 100 + counter,
            );
            let record = |count: U256| {
                *seen.borrow_mut() = Some(count);
                fee(count)
            };
            ledger
                .admit(&req, &view, &record, &test_domain())
                .expect("ok");
            assert_eq!(seen.into_inner(), Some(predicted));
        }

        assert_eq!(
            ledger.projected_total(view.channel_id, 0, 4, view.settled_count),
            U256::from(6),
            "lane 0 at 4 plus lane 1 at 2"
        );
        assert_eq!(
            ledger.projected_total(view.channel_id, 2, 1, view.settled_count),
            U256::from(6),
            "an untouched lane adds its own counter"
        );
        assert_eq!(
            ledger.projected_total(B256::ZERO, 0, 1, U256::from(9)),
            U256::from(9),
            "clamped to the on-chain settled count"
        );
    }

    #[test]
    fn settlement_batch_keeps_only_the_highest_per_lane() {
        let key = signer(1);
        let view = view(key.address(), 10);
        let mut ledger = Ledger::new();

        for (lane, counter) in [(0u32, 1u64), (0, 2), (1, 1), (0, 3), (1, 2)] {
            let req = signed(
                &key,
                view.channel_id,
                LaneNonce::new(lane, counter),
                RP_ID,
                u64::from(lane) * 100 + counter,
            );
            ledger.admit(&req, &view, &fee, &test_domain()).expect("ok");
        }

        let batch = ledger.settlement_batch(view.channel_id);
        assert_eq!(batch.len(), 2, "one authorisation per lane");
        assert_eq!(batch[0].channel_nonce, LaneNonce::new(0, 3).pack());
        assert_eq!(batch[1].channel_nonce, LaneNonce::new(1, 2).pack());

        ledger.mark_settled(view.channel_id);
        assert!(ledger.settlement_batch(view.channel_id).is_empty());
        assert_eq!(
            ledger.high_water(view.channel_id, 0),
            3,
            "high-water marks survive settlement"
        );
    }

    /// After settling, a fresh view reports the paid amount; the next admission must charge the
    /// delta rather than the whole cumulative fee again.
    #[test]
    fn settled_state_is_not_double_charged() {
        let key = signer(1);
        let mut view = view(key.address(), 3);
        let mut ledger = Ledger::new();

        for counter in 1..=3u64 {
            let req = signed(
                &key,
                view.channel_id,
                LaneNonce::new(0, counter),
                RP_ID,
                counter,
            );
            ledger.admit(&req, &view, &fee, &test_domain()).expect("ok");
        }
        ledger.mark_settled(view.channel_id);

        view.paid = U256::from(3) * U256::from(PRICE);
        view.balance = U256::ZERO;
        view.settled_count = U256::from(3);

        let req = signed(&key, view.channel_id, LaneNonce::new(0, 4), RP_ID, 4);
        assert!(
            matches!(
                ledger.admit(&req, &view, &fee, &test_domain()),
                Err(AdmitError::Insolvent { .. })
            ),
            "an empty channel cannot fund more work"
        );

        view.balance = U256::from(PRICE);
        ledger
            .admit(&req, &view, &fee, &test_domain())
            .expect("one more unit is affordable after a top-up");
    }
}
