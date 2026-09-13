//! The collector's ledger: issues nonces, admits payments, and batches settlements.
//!
//! In-memory and single-process. A real collector must persist every reservation before
//! returning it and every admitted payment before doing the work, and must serialise these
//! operations per `(channel, epoch)`; two concurrent admissions against one lane would
//! otherwise both pass the capacity check.

use std::collections::{BTreeSet, HashMap};

use alloy::sol_types::Eip712Domain;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::{
    nonce::{LaneNonce, NonceError},
    payment::{Payment, PaymentError},
    typed_data::{ChannelSettings, epoch_of},
};

/// A chain read that could not be trusted, so the caller must refuse rather than serve.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("chain state for channel {channel_id} epoch {epoch} is stale or unavailable: {reason}")]
pub struct StaleOrUnavailable {
    /// Channel whose state could not be read.
    pub channel_id: B256,
    /// Epoch whose state could not be read.
    pub epoch: u64,
    /// What went wrong, for the failure log.
    pub reason: String,
}

/// A snapshot of the escrow's per-epoch capacity, `funded / pricePerUnit`.
///
/// Implementations must fail rather than guess: a stale or unreachable chain is the one case
/// where the collector is obliged to refuse work it might otherwise be paid for.
pub trait ChainView {
    /// Units this epoch has been funded for.
    ///
    /// # Errors
    /// Returns [`StaleOrUnavailable`] when the snapshot is older than the implementation's
    /// declared staleness bound, or when the read failed.
    fn capacity(&self, channel_id: B256, epoch: u64) -> Result<u64, StaleOrUnavailable>;
}

/// Bounds the collector enforces on itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerConfig {
    /// Longest a payment may live before presentation. Sets every reservation's `expires_by`.
    pub max_request_lifetime: u64,
    /// Pending reservations allowed per `(channel, epoch)`, bounding lane growth.
    pub max_pending_per_epoch: usize,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            max_request_lifetime: 300,
            max_pending_per_epoch: 64,
        }
    }
}

/// A nonce the collector issued and the RP has not signed yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedNonce {
    /// Lane the counter belongs to.
    pub lane: u32,
    /// Counter to sign, one above the lane's highest signed counter.
    pub counter: u64,
    /// Last second at which the signed payment may be presented.
    pub expires_by: u64,
    /// The RP's own payment for `counter - 1`, or `null` when `counter` is 1.
    pub previous: Option<Payment>,
}

impl IssuedNonce {
    /// The nonce to sign.
    #[must_use]
    pub const fn lane_nonce(&self) -> LaneNonce {
        LaneNonce::new(self.lane, self.counter)
    }
}

/// One admitted unit of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmittedUnit {
    /// Epoch the unit is billed to.
    pub epoch: u64,
    /// Lane and counter the unit consumed.
    pub lane_nonce: LaneNonce,
}

/// Why the collector refused to issue a nonce.
#[derive(Debug, thiserror::Error)]
pub enum ReserveError {
    /// The channel is not one this collector serves.
    #[error("unknown channel {0}")]
    UnknownChannel(B256),
    /// The epoch is neither the current one nor the next one.
    #[error("epoch {asked} is not the current epoch {current} or the one after it")]
    EpochOutOfRange {
        /// Epoch the caller asked for.
        asked: u64,
        /// Epoch the collector's clock is in.
        current: u64,
    },
    /// `now` falls outside the channel's schedule, so there is no current epoch.
    #[error("the channel has no epoch at {0}")]
    NoCurrentEpoch(u64),
    /// The chain read failed or was stale, so the collector fails closed.
    #[error(transparent)]
    Chain(#[from] StaleOrUnavailable),
    /// Issuing another nonce could take the epoch past what it was funded for.
    #[error("epoch {epoch} is full: {admitted} admitted and {pending} pending of {capacity}")]
    CapacityExhausted {
        /// Epoch that ran out.
        epoch: u64,
        /// Units already admitted.
        admitted: u64,
        /// Nonces issued but not yet signed.
        pending: u64,
        /// Units the epoch was funded for.
        capacity: u64,
    },
    /// Too many nonces are outstanding, so a client cannot exhaust the collector's memory.
    #[error("epoch {epoch} already has {pending} pending reservations, the limit is {limit}")]
    TooManyPending {
        /// Epoch that hit the bound.
        epoch: u64,
        /// Nonces issued but not yet signed.
        pending: u64,
        /// The configured bound.
        limit: usize,
    },
    /// The lane's counter space ran out.
    #[error(transparent)]
    Nonce(#[from] NonceError),
}

/// Why the collector refused a payment, whether it arrived early or with the work request.
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    /// The payment names a channel this collector does not serve.
    #[error("unknown channel {0}")]
    UnknownChannel(B256),
    /// The payment did not verify against the channel.
    #[error(transparent)]
    Payment(#[from] PaymentError),
    /// No reservation on that lane is waiting for that counter.
    #[error("lane {lane} has no reservation for counter {counter} in epoch {epoch}")]
    UnknownReservation {
        /// Epoch named by the payment.
        epoch: u64,
        /// Lane named by the nonce.
        lane: u32,
        /// Counter named by the nonce.
        counter: u64,
    },
    /// The reservation belongs to a different request id.
    #[error("lane {lane} counter {counter} was reissued to another request")]
    ReservationSuperseded {
        /// Lane named by the nonce.
        lane: u32,
        /// Counter named by the nonce.
        counter: u64,
    },
    /// The reservation lapsed, so the payment can no longer be presented.
    #[error("the reservation for lane {lane} counter {counter} expired at {expires_by}")]
    ReservationExpired {
        /// Lane named by the nonce.
        lane: u32,
        /// Counter named by the nonce.
        counter: u64,
        /// The reservation's deadline.
        expires_by: u64,
    },
    /// The payment was already consumed. It pays for one unit, not one per presentation.
    #[error("lane {lane} counter {counter} in epoch {epoch} was already admitted")]
    AlreadyAdmitted {
        /// Epoch named by the payment.
        epoch: u64,
        /// Lane named by the nonce.
        lane: u32,
        /// Counter named by the nonce.
        counter: u64,
    },
    /// The epoch has no funded capacity left. Refuse with a proof; do not do the work.
    #[error("epoch {epoch} has admitted {admitted} of {capacity} funded units")]
    CapacityExhausted {
        /// Epoch that ran out.
        epoch: u64,
        /// Units already admitted.
        admitted: u64,
        /// Units the epoch was funded for.
        capacity: u64,
    },
    /// The chain read failed or was stale, so the collector fails closed.
    #[error(transparent)]
    Chain(#[from] StaleOrUnavailable),
}

impl AdmitError {
    /// Stable refusal class for metrics and for the wire.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::UnknownChannel(_) => "unknown_channel",
            Self::Payment(_) => "invalid_payment",
            Self::UnknownReservation { .. } => "unknown_reservation",
            Self::ReservationSuperseded { .. } => "reservation_superseded",
            Self::ReservationExpired { .. } => "reservation_expired",
            Self::AlreadyAdmitted { .. } => "already_admitted",
            Self::CapacityExhausted { .. } => "capacity_exhausted",
            Self::Chain(_) => "chain_unavailable",
        }
    }
}

/// A nonce issued and awaiting the RP's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reservation {
    counter: u64,
    request_id: String,
    expires_by: u64,
}

/// Per-lane state within one epoch.
#[derive(Debug, Clone, Default)]
struct Lane {
    /// Highest payment the RP has signed on this lane, the proof of its usage.
    latest: Option<Payment>,
    /// The one outstanding nonce on this lane, if any.
    pending: Option<Reservation>,
    /// Counters already consumed, so a payment is admitted at most once.
    admitted: BTreeSet<u64>,
    /// Highest counter known to be on chain.
    settled_mark: u64,
}

/// Per-`(channel, epoch)` state. Dropped once the epoch is closed.
#[derive(Debug, Clone, Default)]
struct Epoch {
    lanes: Vec<Lane>,
    by_request_id: HashMap<String, (u32, u64)>,
    admitted_units: u64,
}

impl Epoch {
    fn lane(&self, lane: u32) -> Option<&Lane> {
        self.lanes.get(lane as usize)
    }

    /// Reservations that can still be signed against.
    fn live_pending(&self, now: u64) -> u64 {
        self.lanes
            .iter()
            .filter(|lane| {
                lane.pending
                    .as_ref()
                    .is_some_and(|pending| now < pending.expires_by)
            })
            .count() as u64
    }
}

/// The collector's off-chain record of issued nonces and admitted units.
#[derive(Debug)]
pub struct Ledger<V> {
    domain: Eip712Domain,
    chain: V,
    config: LedgerConfig,
    channels: HashMap<B256, ChannelSettings>,
    epochs: HashMap<(B256, u64), Epoch>,
}

impl<V: ChainView> Ledger<V> {
    /// Creates an empty ledger serving the escrow described by `domain`.
    #[must_use]
    pub fn new(domain: Eip712Domain, chain: V, config: LedgerConfig) -> Self {
        Self {
            domain,
            chain,
            config,
            channels: HashMap::new(),
            epochs: HashMap::new(),
        }
    }

    /// Registers a channel this collector serves, returning its id.
    ///
    /// The caller is responsible for checking `settings.collector` is this service and that
    /// the channel is open on chain; the ledger only pays attention to channels it was told
    /// about.
    pub fn register_channel(&mut self, settings: ChannelSettings) -> B256 {
        let channel_id = settings.channel_id(&self.domain);
        self.channels.insert(channel_id, settings);
        channel_id
    }

    /// The settings of a registered channel.
    #[must_use]
    pub fn settings(&self, channel_id: B256) -> Option<&ChannelSettings> {
        self.channels.get(&channel_id)
    }

    /// Units admitted in an epoch, settled or not.
    #[must_use]
    pub fn admitted_units(&self, channel_id: B256, epoch: u64) -> u64 {
        self.epochs
            .get(&(channel_id, epoch))
            .map_or(0, |epoch| epoch.admitted_units)
    }

    /// Issues the next counter on the lowest free lane, with the proof the RP needs.
    ///
    /// Idempotent on `request_id` while the reservation it created is still pending.
    ///
    /// # Errors
    /// See [`ReserveError`].
    pub fn reserve(
        &mut self,
        channel_id: B256,
        epoch: u64,
        request_id: &str,
        now: u64,
    ) -> Result<IssuedNonce, ReserveError> {
        let settings = self
            .channels
            .get(&channel_id)
            .ok_or(ReserveError::UnknownChannel(channel_id))?;

        // A payment cannot outlive its reservation, so there is no reason to issue a counter
        // for an epoch that has already ended or is more than one epoch away.
        let current = epoch_of(now, settings).ok_or(ReserveError::NoCurrentEpoch(now))?;
        if epoch != current && epoch != current.saturating_add(1) {
            return Err(ReserveError::EpochOutOfRange {
                asked: epoch,
                current,
            });
        }

        // Fail closed: capacity is read before anything is handed out.
        let capacity = self.chain.capacity(channel_id, epoch)?;
        let config = self.config;
        let state = self.epochs.entry((channel_id, epoch)).or_default();

        if let Some(issued) = state.replay(request_id) {
            return Ok(issued);
        }

        let pending = state.live_pending(now);
        if state.admitted_units.saturating_add(pending) >= capacity {
            return Err(ReserveError::CapacityExhausted {
                epoch,
                admitted: state.admitted_units,
                pending,
                capacity,
            });
        }
        if pending >= config.max_pending_per_epoch as u64 {
            return Err(ReserveError::TooManyPending {
                epoch,
                pending,
                limit: config.max_pending_per_epoch,
            });
        }

        let index = state.pick_lane(now);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "lane count is bounded by max_pending_per_epoch, far below u32::MAX"
        )]
        let lane_id = index as u32;
        let lane = state
            .lanes
            .get_mut(index)
            .ok_or(NonceError::LaneExhausted { lane: lane_id })?;

        // The counter the collector may propose is exactly one above the highest the RP has
        // signed on this lane. A reissue after `expires_by` therefore repeats the same
        // counter: every payment signed with it has already lapsed.
        let counter = lane
            .latest
            .as_ref()
            .and_then(|latest| latest.lane_nonce().ok())
            .map_or(0, |nonce| nonce.counter)
            .checked_add(1)
            .ok_or(NonceError::LaneExhausted { lane: lane_id })?;
        let expires_by = now.saturating_add(config.max_request_lifetime);

        if let Some(superseded) = lane.pending.replace(Reservation {
            counter,
            request_id: request_id.to_string(),
            expires_by,
        }) {
            state.by_request_id.remove(&superseded.request_id);
        }
        let previous = lane.latest.clone();
        state
            .by_request_id
            .insert(request_id.to_string(), (lane_id, counter));

        Ok(IssuedNonce {
            lane: lane_id,
            counter,
            expires_by,
            previous,
        })
    }

    /// Consumes a payment: the work-request path.
    ///
    /// Runs the spec's five checks in order: channel, reservation, first presentation,
    /// signature, capacity. Nothing is recorded unless every one of them passes.
    ///
    /// # Errors
    /// See [`AdmitError`].
    pub fn admit(&mut self, payment: &Payment, now: u64) -> Result<AdmittedUnit, AdmitError> {
        self.consume(payment, None, true, now)
    }

    /// Banks a payment returned early, before the user presents it.
    ///
    /// Frees the lane at once, so lanes track the RP's signing concurrency rather than how
    /// long users take. The unit is charged whether or not the work is ever requested.
    /// Capacity is not re-checked here: [`Self::reserve`] already gated this counter against
    /// it, and the alternative is a lane stuck on a counter the RP has signed.
    ///
    /// # Errors
    /// See [`AdmitError`].
    pub fn record(
        &mut self,
        payment: &Payment,
        request_id: &str,
        now: u64,
    ) -> Result<AdmittedUnit, AdmitError> {
        self.consume(payment, Some(request_id), false, now)
    }

    /// The one admission path. `request_id`, when given, must own the reservation.
    fn consume(
        &mut self,
        payment: &Payment,
        request_id: Option<&str>,
        check_capacity: bool,
        now: u64,
    ) -> Result<AdmittedUnit, AdmitError> {
        // 1.
        let channel_id = payment.channel_id;
        let settings = self
            .channels
            .get(&channel_id)
            .ok_or(AdmitError::UnknownChannel(channel_id))?;
        let epoch = payment.epoch;
        let spend_key = settings.spendKey;
        let lane_nonce = payment.lane_nonce().map_err(PaymentError::from)?;
        let unit = AdmittedUnit { epoch, lane_nonce };

        let state =
            self.epochs
                .get_mut(&(channel_id, epoch))
                .ok_or(AdmitError::UnknownReservation {
                    epoch,
                    lane: lane_nonce.lane,
                    counter: lane_nonce.counter,
                })?;
        let lane = state
            .lane(lane_nonce.lane)
            .ok_or(AdmitError::UnknownReservation {
                epoch,
                lane: lane_nonce.lane,
                counter: lane_nonce.counter,
            })?;

        // 3, before 2 so a replay reports being spent rather than losing its reservation.
        if lane.admitted.contains(&lane_nonce.counter) {
            return Err(AdmitError::AlreadyAdmitted {
                epoch,
                lane: lane_nonce.lane,
                counter: lane_nonce.counter,
            });
        }

        // 2.
        let pending = lane
            .pending
            .as_ref()
            .filter(|pending| pending.counter == lane_nonce.counter)
            .ok_or(AdmitError::UnknownReservation {
                epoch,
                lane: lane_nonce.lane,
                counter: lane_nonce.counter,
            })?;
        if let Some(request_id) = request_id
            && pending.request_id != request_id
        {
            return Err(AdmitError::ReservationSuperseded {
                lane: lane_nonce.lane,
                counter: lane_nonce.counter,
            });
        }
        if now >= pending.expires_by {
            return Err(AdmitError::ReservationExpired {
                lane: lane_nonce.lane,
                counter: lane_nonce.counter,
                expires_by: pending.expires_by,
            });
        }

        // 4.
        payment.verify(channel_id, epoch, spend_key, &self.domain)?;

        // 5. Read last, so a capacity refusal is the only reason a valid payment is turned away.
        if check_capacity {
            let capacity = self.chain.capacity(channel_id, epoch)?;
            let admitted = state.admitted_units;
            if admitted >= capacity {
                return Err(AdmitError::CapacityExhausted {
                    epoch,
                    admitted,
                    capacity,
                });
            }
        }

        state.commit(lane_nonce, payment.clone());
        Ok(unit)
    }

    /// The highest payment per lane: what the RP must check to believe a refusal.
    ///
    /// The RP verifies its own signatures and sums the counters, so the proof costs one
    /// signature per lane rather than one per unit.
    #[must_use]
    pub fn refusal_proof(&self, channel_id: B256, epoch: u64) -> Vec<Payment> {
        self.epochs
            .get(&(channel_id, epoch))
            .map(|state| {
                state
                    .lanes
                    .iter()
                    .filter_map(|l| l.latest.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The payments worth submitting: the highest per lane above its settled mark.
    #[must_use]
    pub fn settlement_batch(&self, channel_id: B256, epoch: u64) -> Vec<Payment> {
        self.epochs
            .get(&(channel_id, epoch))
            .map(|state| {
                state
                    .lanes
                    .iter()
                    .filter_map(|lane| {
                        let latest = lane.latest.as_ref()?;
                        (latest.lane_nonce().ok()?.counter > lane.settled_mark)
                            .then(|| latest.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Records that `settled` is now on chain, so the next batch does not repeat it.
    pub fn mark_settled(&mut self, channel_id: B256, epoch: u64, settled: &[Payment]) {
        let Some(state) = self.epochs.get_mut(&(channel_id, epoch)) else {
            return;
        };
        for nonce in settled.iter().filter_map(|p| p.lane_nonce().ok()) {
            if let Some(lane) = state.lanes.get_mut(nonce.lane as usize) {
                lane.settled_mark = lane.settled_mark.max(nonce.counter);
            }
        }
    }

    /// Drops every record for a closed epoch. Nothing more can be settled for it.
    pub fn close_epoch(&mut self, channel_id: B256, epoch: u64) {
        self.epochs.remove(&(channel_id, epoch));
    }
}

impl Epoch {
    /// The reservation this `request_id` already holds, if it is still the lane's pending one.
    fn replay(&self, request_id: &str) -> Option<IssuedNonce> {
        let &(lane_id, counter) = self.by_request_id.get(request_id)?;
        let lane = self.lane(lane_id)?;
        let pending = lane.pending.as_ref()?;
        (pending.counter == counter && pending.request_id == request_id).then(|| IssuedNonce {
            lane: lane_id,
            counter,
            expires_by: pending.expires_by,
            previous: lane.latest.clone(),
        })
    }

    /// Lowest lane with no pending nonce, else the lowest whose nonce lapsed, else a new one.
    fn pick_lane(&mut self, now: u64) -> usize {
        if let Some(free) = self.lanes.iter().position(|lane| lane.pending.is_none()) {
            return free;
        }
        if let Some(stale) = self.lanes.iter().position(|lane| {
            lane.pending
                .as_ref()
                .is_some_and(|pending| now >= pending.expires_by)
        }) {
            return stale;
        }
        self.lanes.push(Lane::default());
        self.lanes.len() - 1
    }

    /// Books a verified payment. The caller has already run every check.
    fn commit(&mut self, lane_nonce: LaneNonce, payment: Payment) {
        let Some(lane) = self.lanes.get_mut(lane_nonce.lane as usize) else {
            return;
        };
        if let Some(pending) = lane
            .pending
            .as_ref()
            .filter(|p| p.counter == lane_nonce.counter)
        {
            self.by_request_id.remove(&pending.request_id);
            lane.pending = None;
        }
        lane.admitted.insert(lane_nonce.counter);
        let higher = lane
            .latest
            .as_ref()
            .and_then(|latest| latest.lane_nonce().ok())
            .is_none_or(|latest| lane_nonce.counter > latest.counter);
        if higher {
            lane.latest = Some(payment);
        }
        self.admitted_units += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        payment::tests::paid,
        typed_data::tests::{EPOCH_LENGTH, EPOCH_ZERO, settings, signer, test_domain},
    };
    use alloy::signers::local::PrivateKeySigner;
    use std::cell::Cell;

    /// Wall clock the tests work at: five seconds into epoch 0.
    const NOW: u64 = EPOCH_ZERO + 5;
    /// Epoch every test reserves and admits in.
    const EPOCH: u64 = 0;

    /// A stubbed chain read the tests drive by hand.
    #[derive(Debug, Default)]
    struct Stub {
        capacity: Cell<u64>,
        available: Cell<bool>,
    }

    impl Stub {
        fn with_capacity(units: u64) -> Self {
            Self {
                capacity: Cell::new(units),
                available: Cell::new(true),
            }
        }
    }

    impl ChainView for Stub {
        fn capacity(&self, channel_id: B256, epoch: u64) -> Result<u64, StaleOrUnavailable> {
            if self.available.get() {
                Ok(self.capacity.get())
            } else {
                Err(StaleOrUnavailable {
                    channel_id,
                    epoch,
                    reason: "stubbed outage".to_string(),
                })
            }
        }
    }

    struct Fixture {
        ledger: Ledger<Stub>,
        channel_id: B256,
        key: PrivateKeySigner,
    }

    impl Fixture {
        fn new(capacity: u64) -> Self {
            Self::with_config(capacity, LedgerConfig::default())
        }

        fn with_config(capacity: u64, config: LedgerConfig) -> Self {
            let key = signer(1);
            let mut ledger = Ledger::new(test_domain(), Stub::with_capacity(capacity), config);
            let channel_id = ledger.register_channel(settings(key.address()));
            Self {
                ledger,
                channel_id,
                key,
            }
        }

        fn reserve(&mut self, request_id: &str, now: u64) -> Result<IssuedNonce, ReserveError> {
            self.ledger.reserve(self.channel_id, EPOCH, request_id, now)
        }

        /// Reserves, signs, and admits one unit, the whole happy path.
        fn one_unit(&mut self, request_id: &str, now: u64) -> AdmittedUnit {
            let issued = self.reserve(request_id, now).expect("reserves");
            let payment = paid(&self.key, EPOCH, issued.lane_nonce());
            self.ledger.admit(&payment, now).expect("admits")
        }
    }

    #[test]
    fn a_first_nonce_has_no_predecessor() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        assert_eq!((issued.lane, issued.counter), (0, 1));
        assert_eq!(issued.previous, None, "counter 1 has no predecessor");
        assert_eq!(
            issued.expires_by,
            NOW + LedgerConfig::default().max_request_lifetime
        );
    }

    #[test]
    fn retrying_the_same_request_id_returns_the_same_reservation() {
        let mut fx = Fixture::new(10);
        let first = fx.reserve("r1", NOW).expect("reserves");
        let again = fx.reserve("r1", NOW + 1).expect("reserves");
        assert_eq!(first, again, "idempotent on request id");
    }

    #[test]
    fn one_reservation_per_lane_so_concurrency_spreads_across_lanes() {
        let mut fx = Fixture::new(10);
        let first = fx.reserve("r1", NOW).expect("reserves");
        let second = fx.reserve("r2", NOW).expect("reserves");
        let third = fx.reserve("r3", NOW).expect("reserves");

        assert_eq!((first.lane, first.counter), (0, 1));
        assert_eq!((second.lane, second.counter), (1, 1));
        assert_eq!((third.lane, third.counter), (2, 1));
    }

    #[test]
    fn admitting_frees_the_lane_and_the_next_counter_carries_the_predecessor() {
        let mut fx = Fixture::new(10);
        fx.one_unit("r1", NOW);

        let next = fx.reserve("r2", NOW).expect("reserves");
        assert_eq!((next.lane, next.counter), (0, 2), "the lane was freed");
        let previous = next.previous.as_ref().expect("counter 2 has a predecessor");
        assert_eq!(
            previous
                .verify(fx.channel_id, EPOCH, fx.key.address(), &test_domain())
                .expect("verifies"),
            LaneNonce::new(0, 1),
            "the proof is the RP's own signature"
        );
    }

    #[test]
    fn a_lapsed_reservation_is_reissued_with_the_same_counter() {
        let lifetime = LedgerConfig::default().max_request_lifetime;
        let mut fx = Fixture::new(10);
        let first = fx.reserve("r1", NOW).expect("reserves");
        let reissued = fx.reserve("r2", NOW + lifetime).expect("reserves");

        assert_eq!(
            (reissued.lane, reissued.counter),
            (first.lane, first.counter),
            "no counter is ever skipped"
        );

        // The abandoned payment can no longer be presented: its reservation is gone.
        let abandoned = paid(&fx.key, EPOCH, first.lane_nonce());
        assert!(matches!(
            fx.ledger.record(&abandoned, "r1", NOW + lifetime),
            Err(AdmitError::ReservationSuperseded { .. })
        ));
    }

    #[test]
    fn the_early_put_frees_the_lane_before_the_work_is_requested() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        let payment = paid(&fx.key, EPOCH, issued.lane_nonce());

        fx.ledger.record(&payment, "r1", NOW).expect("records");
        assert_eq!(fx.ledger.admitted_units(fx.channel_id, EPOCH), 1);

        let next = fx.reserve("r2", NOW).expect("reserves");
        assert_eq!((next.lane, next.counter), (0, 2), "same lane, next counter");

        // The payment then arrives with the work request and is already spent.
        assert!(matches!(
            fx.ledger.admit(&payment, NOW),
            Err(AdmitError::AlreadyAdmitted { .. })
        ));
        assert_eq!(
            fx.ledger.admitted_units(fx.channel_id, EPOCH),
            1,
            "charged once"
        );
    }

    #[test]
    fn record_refuses_a_foreign_or_superseded_payment() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        let nonce = issued.lane_nonce();
        let payment = paid(&fx.key, EPOCH, nonce);

        let forged =
            Payment::sign(fx.channel_id, EPOCH, nonce, &signer(2), &test_domain()).expect("signs");
        assert!(matches!(
            fx.ledger.record(&forged, "r1", NOW),
            Err(AdmitError::Payment(PaymentError::SignerMismatch { .. }))
        ));

        assert!(matches!(
            fx.ledger.record(&payment, "other", NOW),
            Err(AdmitError::ReservationSuperseded { .. })
        ));

        assert!(matches!(
            fx.ledger.record(&payment, "r1", issued.expires_by),
            Err(AdmitError::ReservationExpired { .. })
        ));

        let unreserved = paid(&fx.key, EPOCH, LaneNonce::new(0, 9));
        assert!(matches!(
            fx.ledger.record(&unreserved, "r1", NOW),
            Err(AdmitError::UnknownReservation { .. })
        ));
    }

    /// A payment pays for one unit, so a second presentation buys nothing.
    #[test]
    fn a_repeat_of_an_admitted_payment_is_refused() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        let payment = paid(&fx.key, EPOCH, issued.lane_nonce());

        fx.ledger.admit(&payment, NOW).expect("admits");
        assert!(matches!(
            fx.ledger.admit(&payment, NOW),
            Err(AdmitError::AlreadyAdmitted {
                epoch: EPOCH,
                lane: 0,
                counter: 1
            })
        ));
        assert_eq!(fx.ledger.admitted_units(fx.channel_id, EPOCH), 1);
    }

    #[test]
    fn presentation_after_the_reservation_lapses_is_refused() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        let payment = paid(&fx.key, EPOCH, issued.lane_nonce());
        assert!(matches!(
            fx.ledger.admit(&payment, issued.expires_by),
            Err(AdmitError::ReservationExpired { .. })
        ));
    }

    #[test]
    fn a_payment_with_no_reservation_is_refused() {
        let mut fx = Fixture::new(10);
        let payment = paid(&fx.key, EPOCH, LaneNonce::new(0, 1));
        assert!(matches!(
            fx.ledger.admit(&payment, NOW),
            Err(AdmitError::UnknownReservation { .. })
        ));
    }

    #[test]
    fn a_payment_for_an_unknown_channel_is_refused() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        let mut foreign = paid(&fx.key, EPOCH, issued.lane_nonce());
        foreign.channel_id = B256::ZERO;
        assert!(matches!(
            fx.ledger.admit(&foreign, NOW),
            Err(AdmitError::UnknownChannel(_))
        ));
    }

    #[test]
    fn a_payment_for_another_epoch_is_refused() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        // Signed for epoch 1, which has no reservations at all.
        let payment = paid(&fx.key, EPOCH + 1, issued.lane_nonce());
        assert!(matches!(
            fx.ledger.admit(&payment, NOW),
            Err(AdmitError::UnknownReservation { epoch: 1, .. })
        ));
    }

    /// A counter may be reserved only for the epoch in progress or the one after it.
    #[test]
    fn reserve_rejects_an_epoch_out_of_range() {
        let mut fx = Fixture::new(10);
        fx.ledger
            .reserve(fx.channel_id, 1, "next", NOW)
            .expect("the next epoch is reservable");
        assert!(matches!(
            fx.ledger.reserve(fx.channel_id, 2, "later", NOW),
            Err(ReserveError::EpochOutOfRange {
                asked: 2,
                current: 0
            })
        ));
        assert!(
            matches!(
                fx.ledger
                    .reserve(fx.channel_id, 0, "past", NOW + 2 * EPOCH_LENGTH),
                Err(ReserveError::EpochOutOfRange {
                    asked: 0,
                    current: 2
                })
            ),
            "an ended epoch is not reservable"
        );
        assert!(matches!(
            fx.ledger.reserve(fx.channel_id, 0, "early", EPOCH_ZERO - 1),
            Err(ReserveError::NoCurrentEpoch(_))
        ));
    }

    #[test]
    fn admission_stops_at_capacity_and_the_refusal_is_provable() {
        let mut fx = Fixture::new(2);
        fx.one_unit("r1", NOW);
        fx.one_unit("r2", NOW);

        // Reserving a third would push pending past capacity.
        assert!(matches!(
            fx.reserve("r3", NOW),
            Err(ReserveError::CapacityExhausted { capacity: 2, .. })
        ));

        // Even with a reservation in hand, admission checks capacity itself.
        fx.ledger.chain.capacity.set(3);
        let issued = fx.reserve("r3", NOW).expect("reserves");
        let payment = paid(&fx.key, EPOCH, issued.lane_nonce());
        fx.ledger.chain.capacity.set(2);
        assert!(matches!(
            fx.ledger.admit(&payment, NOW),
            Err(AdmitError::CapacityExhausted {
                admitted: 2,
                capacity: 2,
                ..
            })
        ));

        // The proof of usage: one authorisation per lane, summing to the admitted units.
        // Both units ran serially on lane 0, so two units cost one signature.
        let proof = fx.ledger.refusal_proof(fx.channel_id, EPOCH);
        assert_eq!(proof.len(), 1, "one per lane, not one per unit");
        let units: u64 = proof
            .iter()
            .map(|payment| {
                payment
                    .verify(fx.channel_id, EPOCH, fx.key.address(), &test_domain())
                    .expect("recovers to the RP")
                    .counter
            })
            .sum();
        assert_eq!(
            units, 2,
            "counters are cumulative, so they sum to the usage"
        );
    }

    #[test]
    fn funding_more_raises_capacity_and_admission_resumes() {
        let mut fx = Fixture::new(1);
        fx.one_unit("r1", NOW);
        assert!(matches!(
            fx.reserve("r2", NOW),
            Err(ReserveError::CapacityExhausted { .. })
        ));

        fx.ledger.chain.capacity.set(2);
        fx.one_unit("r2", NOW);
        assert_eq!(fx.ledger.admitted_units(fx.channel_id, EPOCH), 2);
    }

    #[test]
    fn a_stale_chain_read_fails_closed() {
        let mut fx = Fixture::new(10);
        let issued = fx.reserve("r1", NOW).expect("reserves");
        let payment = paid(&fx.key, EPOCH, issued.lane_nonce());

        fx.ledger.chain.available.set(false);
        assert!(matches!(
            fx.ledger.admit(&payment, NOW),
            Err(AdmitError::Chain(_))
        ));
        assert!(matches!(fx.reserve("r2", NOW), Err(ReserveError::Chain(_))));
        assert_eq!(
            fx.ledger.admitted_units(fx.channel_id, EPOCH),
            0,
            "nothing served"
        );

        fx.ledger.chain.available.set(true);
        fx.ledger.admit(&payment, NOW).expect("admits");
    }

    #[test]
    fn pending_reservations_are_bounded() {
        let mut fx = Fixture::with_config(
            100,
            LedgerConfig {
                max_pending_per_epoch: 2,
                ..LedgerConfig::default()
            },
        );
        fx.reserve("r1", NOW).expect("reserves");
        fx.reserve("r2", NOW).expect("reserves");
        assert!(matches!(
            fx.reserve("r3", NOW),
            Err(ReserveError::TooManyPending { limit: 2, .. })
        ));
    }

    #[test]
    fn settlement_submits_only_what_is_new() {
        let mut fx = Fixture::new(10);
        fx.one_unit("r1", NOW); // lane 0, counter 1
        fx.one_unit("r2", NOW); // lane 0, counter 2
        fx.one_unit("r3", NOW); // lane 0, counter 3

        let batch = fx.ledger.settlement_batch(fx.channel_id, EPOCH);
        assert_eq!(
            batch.len(),
            1,
            "only the highest per lane is worth settling"
        );
        assert_eq!(batch[0].lane_nonce().expect("nonce"), LaneNonce::new(0, 3));

        fx.ledger.mark_settled(fx.channel_id, EPOCH, &batch);
        assert!(
            fx.ledger.settlement_batch(fx.channel_id, EPOCH).is_empty(),
            "replaying a settled batch pays nothing, so it is not resubmitted"
        );

        fx.one_unit("r4", NOW);
        let batch = fx.ledger.settlement_batch(fx.channel_id, EPOCH);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].lane_nonce().expect("nonce"), LaneNonce::new(0, 4));
    }

    #[test]
    fn multiple_lanes_settle_independently() {
        let mut fx = Fixture::new(10);
        let first = fx.reserve("r1", NOW).expect("reserves");
        let second = fx.reserve("r2", NOW).expect("reserves");
        assert_ne!(first.lane, second.lane);

        for issued in [&first, &second] {
            let payment = paid(&fx.key, EPOCH, issued.lane_nonce());
            fx.ledger.admit(&payment, NOW).expect("admits");
        }

        let batch = fx.ledger.settlement_batch(fx.channel_id, EPOCH);
        assert_eq!(batch.len(), 2);
        let units: u64 = batch
            .iter()
            .map(|p| p.lane_nonce().expect("nonce").counter)
            .sum();
        assert_eq!(units, 2);
    }

    #[test]
    fn closing_an_epoch_drops_its_state() {
        let mut fx = Fixture::new(10);
        fx.one_unit("r1", NOW);
        assert_eq!(fx.ledger.admitted_units(fx.channel_id, EPOCH), 1);

        fx.ledger.close_epoch(fx.channel_id, EPOCH);
        assert_eq!(fx.ledger.admitted_units(fx.channel_id, EPOCH), 0);
        assert!(fx.ledger.settlement_batch(fx.channel_id, EPOCH).is_empty());
        assert!(fx.ledger.refusal_proof(fx.channel_id, EPOCH).is_empty());
    }

    #[test]
    fn an_unregistered_channel_is_not_served() {
        let mut ledger = Ledger::new(
            test_domain(),
            Stub::with_capacity(10),
            LedgerConfig::default(),
        );
        assert!(matches!(
            ledger.reserve(B256::ZERO, EPOCH, "r1", NOW),
            Err(ReserveError::UnknownChannel(_))
        ));
    }
}
