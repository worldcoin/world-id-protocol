//! The billing state a TEE Verifier's host supplies to it (WIP-107 §4.8).
//!
//! A host derives [`BillingOp`]s from the Billing Contract's logs and applies them to its own
//! [`BillingState`]; the Verifier applies the same ops to its copy. Every op is absolute, so a
//! reorganization is undone by applying the inverses [`BillingState::apply`] returned.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::is_period_active;
use crate::{FieldElement, rp::RpId};

/// A World ID's registration in one RP's billing period, as `registrationOf` returns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Registration {
    /// The RP the registration consumed capacity of.
    pub rp_id: RpId,
    /// The start of the registration's billing period.
    pub period_start: u64,
}

/// One change to a [`BillingState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BillingOp {
    /// Sets whether the Billing Contract bills `rp_id`, from a `BilledRpUpdated` log.
    SetBilledRp {
        /// The RP.
        rp_id: RpId,
        /// Whether it is billed.
        billed: bool,
    },
    /// Adds a registration, from a `Registered` log.
    AddRegistration {
        /// The registered `billingNullifier`.
        nullifier: FieldElement,
        /// Its RP and period.
        registration: Registration,
    },
    /// Removes a registration, when a reorganization drops its `Registered` log.
    RemoveRegistration {
        /// The registered `billingNullifier`.
        nullifier: FieldElement,
    },
}

/// Why a [`BillingState`] rejected an op. A rejected op leaves the state unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BillingStateError {
    /// The state already holds its maximum number of registrations.
    #[error("the billing state holds its maximum of {0} registrations")]
    Full(usize),
    /// The nullifier is already registered for another RP or period. The Billing Contract
    /// registers a nullifier at most once, so the source of the ops is broken.
    #[error("the billing nullifier is already registered for another RP or period")]
    Conflict,
}

/// The billed RPs and the registrations a TEE Verifier checks requests against (WIP-107 §4.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BillingState {
    billed_rps: HashSet<RpId>,
    registrations: HashMap<FieldElement, Registration>,
    max_registrations: Option<usize>,
}

impl BillingState {
    /// An empty state that holds at most `max_registrations` registrations.
    #[must_use]
    pub fn with_limit(max_registrations: usize) -> Self {
        Self {
            max_registrations: Some(max_registrations),
            ..Self::default()
        }
    }

    /// Applies `op` and returns the op that undoes it, or `None` if it changed nothing.
    ///
    /// Adding a registration the state already holds with the same values changes nothing, as does
    /// removing one it does not hold.
    ///
    /// # Errors
    /// [`BillingStateError::Full`] when adding beyond the limit, and
    /// [`BillingStateError::Conflict`] when adding a nullifier held with other values.
    pub fn apply(&mut self, op: BillingOp) -> Result<Option<BillingOp>, BillingStateError> {
        match op {
            BillingOp::SetBilledRp { rp_id, billed } => {
                let was_billed = if billed {
                    !self.billed_rps.insert(rp_id)
                } else {
                    self.billed_rps.remove(&rp_id)
                };
                Ok((was_billed != billed).then_some(BillingOp::SetBilledRp {
                    rp_id,
                    billed: was_billed,
                }))
            }
            BillingOp::AddRegistration {
                nullifier,
                registration,
            } => match self.registrations.get(&nullifier) {
                Some(held) if *held == registration => Ok(None),
                Some(_) => Err(BillingStateError::Conflict),
                None => {
                    if let Some(limit) = self.max_registrations
                        && self.registrations.len() >= limit
                    {
                        return Err(BillingStateError::Full(limit));
                    }
                    self.registrations.insert(nullifier, registration);
                    Ok(Some(BillingOp::RemoveRegistration { nullifier }))
                }
            },
            BillingOp::RemoveRegistration { nullifier } => Ok(self
                .registrations
                .remove(&nullifier)
                .map(|registration| BillingOp::AddRegistration {
                    nullifier,
                    registration,
                })),
        }
    }

    /// Whether the Billing Contract bills `rp_id`.
    #[must_use]
    pub fn is_billed(&self, rp_id: RpId) -> bool {
        self.billed_rps.contains(&rp_id)
    }

    /// The registration of `nullifier`, if the state holds one.
    #[must_use]
    pub fn registration(&self, nullifier: FieldElement) -> Option<Registration> {
        self.registrations.get(&nullifier).copied()
    }

    /// Whether `nullifier` is registered for `rp_id` in a context active at `now` (WIP-107 §4.7).
    #[must_use]
    pub fn is_registered(&self, nullifier: FieldElement, rp_id: RpId, now: u64) -> bool {
        self.registration(nullifier).is_some_and(|registration| {
            registration.rp_id == rp_id && is_period_active(registration.period_start, now)
        })
    }

    /// Drops the registrations whose context is no longer active at `now`, and returns how many.
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.registrations.len();
        self.registrations
            .retain(|_, registration| is_period_active(registration.period_start, now));
        before - self.registrations.len()
    }

    /// The ops that rebuild this state from an empty one, e.g. for a Verifier that rebooted.
    pub fn snapshot(&self) -> impl Iterator<Item = BillingOp> + '_ {
        let billed = self.billed_rps.iter().map(|&rp_id| BillingOp::SetBilledRp {
            rp_id,
            billed: true,
        });
        let registered = self
            .registrations
            .iter()
            .map(|(&nullifier, &registration)| BillingOp::AddRegistration {
                nullifier,
                registration,
            });
        billed.chain(registered)
    }

    /// The number of billed RPs.
    #[must_use]
    pub fn billed_rp_count(&self) -> usize {
        self.billed_rps.len()
    }

    /// The number of registrations held.
    #[must_use]
    pub fn registration_count(&self) -> usize {
        self.registrations.len()
    }

    /// Whether the state holds its maximum number of registrations.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.max_registrations
            .is_some_and(|limit| self.registrations.len() >= limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::PERIOD_OVERLAP;

    // 1 Nov and 1 Dec 2026, 00:00:00 AoE.
    const NOV_2026: u64 = 1_793_534_400;
    const DEC_2026: u64 = 1_796_126_400;

    fn nullifier(value: u64) -> FieldElement {
        FieldElement::from(value)
    }

    fn add(value: u64, rp_id: u64, period_start: u64) -> BillingOp {
        BillingOp::AddRegistration {
            nullifier: nullifier(value),
            registration: Registration {
                rp_id: RpId::new(rp_id),
                period_start,
            },
        }
    }

    const fn bill(rp_id: u64, billed: bool) -> BillingOp {
        BillingOp::SetBilledRp {
            rp_id: RpId::new(rp_id),
            billed,
        }
    }

    #[test]
    fn inverses_undo_every_change() {
        let mut state = BillingState::default();
        state.apply(add(1, 7, NOV_2026)).unwrap();
        state.apply(bill(8, true)).unwrap();
        let before = state.clone();

        let ops = [
            add(2, 7, NOV_2026),
            bill(7, true),
            bill(8, false),
            BillingOp::RemoveRegistration {
                nullifier: nullifier(1),
            },
        ];
        let inverses: Vec<_> = ops
            .into_iter()
            .map(|op| {
                state
                    .apply(op)
                    .unwrap()
                    .expect("every op changes something")
            })
            .collect();
        assert!(state.is_billed(RpId::new(7)));
        assert!(!state.is_billed(RpId::new(8)));
        assert_eq!(state.registration(nullifier(1)), None);

        for inverse in inverses.into_iter().rev() {
            state.apply(inverse).unwrap();
        }
        assert_eq!(state, before);
    }

    #[test]
    fn ops_that_change_nothing_have_no_inverse() {
        let mut state = BillingState::default();
        state.apply(add(1, 7, NOV_2026)).unwrap();
        state.apply(bill(7, true)).unwrap();
        assert_eq!(state.apply(add(1, 7, NOV_2026)), Ok(None));
        assert_eq!(state.apply(bill(7, true)), Ok(None));
        assert_eq!(state.apply(bill(9, false)), Ok(None));
        assert_eq!(
            state.apply(BillingOp::RemoveRegistration {
                nullifier: nullifier(2)
            }),
            Ok(None)
        );
    }

    #[test]
    fn a_nullifier_registered_elsewhere_is_a_conflict() {
        let mut state = BillingState::default();
        state.apply(add(1, 7, NOV_2026)).unwrap();
        let before = state.clone();
        for conflicting in [add(1, 8, NOV_2026), add(1, 7, DEC_2026)] {
            assert_eq!(state.apply(conflicting), Err(BillingStateError::Conflict));
        }
        assert_eq!(state, before);
    }

    #[test]
    fn the_limit_bounds_registrations_only() {
        let mut state = BillingState::with_limit(1);
        state.apply(add(1, 7, NOV_2026)).unwrap();
        assert!(state.is_full());
        assert_eq!(
            state.apply(add(2, 7, NOV_2026)),
            Err(BillingStateError::Full(1))
        );
        assert_eq!(state.apply(add(1, 7, NOV_2026)), Ok(None));
        state.apply(bill(7, true)).unwrap();
        assert_eq!(state.registration_count(), 1);
        assert_eq!(state.billed_rp_count(), 1);
    }

    #[test]
    fn registrations_count_only_for_their_rp_while_active() {
        let mut state = BillingState::default();
        state.apply(add(1, 7, DEC_2026)).unwrap();
        let rp = RpId::new(7);
        assert!(!state.is_registered(nullifier(1), rp, DEC_2026 - PERIOD_OVERLAP - 1));
        assert!(state.is_registered(nullifier(1), rp, DEC_2026 - PERIOD_OVERLAP));
        assert!(state.is_registered(nullifier(1), rp, DEC_2026 + 1));
        assert!(!state.is_registered(nullifier(1), RpId::new(8), DEC_2026 + 1));
        assert!(!state.is_registered(nullifier(2), rp, DEC_2026 + 1));
    }

    #[test]
    fn expiry_drops_registrations_of_ended_periods() {
        let mut state = BillingState::default();
        state.apply(add(1, 7, NOV_2026)).unwrap();
        state.apply(add(2, 7, DEC_2026)).unwrap();
        // During December's overlap both periods are active.
        assert_eq!(state.expire(DEC_2026 - 1), 0);
        assert_eq!(state.expire(DEC_2026), 1);
        assert_eq!(state.registration(nullifier(1)), None);
        assert!(state.registration(nullifier(2)).is_some());
    }

    #[test]
    fn a_snapshot_rebuilds_an_equal_state() {
        let mut state = BillingState::with_limit(10);
        state.apply(bill(7, true)).unwrap();
        state.apply(bill(9, true)).unwrap();
        state.apply(bill(9, false)).unwrap();
        state.apply(add(1, 7, NOV_2026)).unwrap();
        state.apply(add(2, 8, DEC_2026)).unwrap();

        let mut rebuilt = BillingState::with_limit(10);
        for op in state.snapshot() {
            rebuilt.apply(op).unwrap();
        }
        assert_eq!(rebuilt, state);
    }

    #[test]
    fn ops_round_trip_through_serde() {
        for op in [
            bill(7, true),
            add(1, 7, NOV_2026),
            BillingOp::RemoveRegistration {
                nullifier: nullifier(1),
            },
        ] {
            let json = serde_json::to_string(&op).unwrap();
            assert_eq!(serde_json::from_str::<BillingOp>(&json).unwrap(), op);
        }
    }
}
