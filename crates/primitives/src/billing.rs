//! Types and helpers for WIP-107 per-period World ID fees.
//!
//! A [`BillingContext`] names one RP's billing period. Its [`BillingContext::billing_action`]
//! is the OPRF action of the period's billing query, and [`billing_nullifier`] finalizes that
//! query into the `billingNullifier` the Billing Contract registers. Period boundaries follow
//! the Anywhere on Earth (AoE) calendar months of WIP-107 §4.3.
//!
//! [`BillingState`] holds the billed RPs and registrations a TEE Verifier checks requests
//! against, built from [`BillingOp`]s its host derives from the Billing Contract's logs (§4.8).
//!
//! Everything but [`BILLED_ACTION_PREFIX`] builds without the `protocol` feature, so a TEE
//! Verifier can check billing state without the proof and OPRF dependencies.

use alloy_primitives::{Address, U256, keccak256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

#[cfg(feature = "protocol")]
use crate::OprfPrefix;
use crate::{
    FieldElement, Nullifier, PrimitiveError,
    authenticator::oprf_query_digest,
    poseidon::{self, ds},
    rp::RpId,
};

#[cfg(feature = "protocol")]
mod registration;
mod state;
#[cfg(feature = "protocol")]
pub use registration::{
    BillingRegistration, BillingWitness, RegistrationAuthorization, registration_period_start,
};
pub use state::{BillingOp, BillingState, BillingStateError, Registration};

/// The most significant byte an RP-signed action MUST carry to authorize a billing registration
/// (WIP-107 §4.1). Reserved for Proofs of Embedding Similarity.
#[cfg(feature = "protocol")]
pub const BILLED_ACTION_PREFIX: OprfPrefix = OprfPrefix::EmbeddingSimilarity;

/// Domain of the billing action, `BILLING_ACTION_DOMAIN` in the Billing Contract (WIP-107 §4.3).
pub const BILLING_ACTION_DOMAIN: &str = "world-id-billing-v1";

/// Overlap between consecutive billing periods, in seconds (WIP-107 §4.1).
pub const PERIOD_OVERLAP: u64 = 93_600;

/// Maximum age of an `isBilledRp` read a TEE Verifier relies on, in seconds (WIP-107 §4.1).
pub const MAX_RP_STATUS_AGE: u64 = 60;

/// Offset of 00:00:00 AoE (UTC−12:00) from 00:00:00 UTC, in seconds.
const AOE_OFFSET: u64 = 12 * 60 * 60;

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// One RP's billing period on one Billing Contract, `BillingContext` in WIP-107 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BillingContext {
    /// The chain hosting the Billing Contract.
    pub chain_id: U256,
    /// The Billing Contract's address.
    pub billing_contract: Address,
    /// The billed RP.
    pub rp_id: RpId,
    /// The period's start, 00:00:00 AoE on the first day of a month.
    pub period_start: u64,
}

impl BillingContext {
    /// The billing action: `keccak256(abi.encode(BILLING_ACTION_DOMAIN, chainId, billingContract,
    /// rpId, periodStart)) >> 8`, as `getBillingAction` computes it (WIP-107 §4.3).
    ///
    /// The shift leaves the most significant byte `0x00`, so the action is always in the field.
    #[must_use]
    pub fn billing_action(&self) -> FieldElement {
        let encoded = (
            BILLING_ACTION_DOMAIN,
            self.chain_id,
            self.billing_contract,
            self.rp_id.into_inner(),
            self.period_start,
        )
            .abi_encode_params();
        let action: U256 = U256::from_be_bytes(keccak256(encoded).0) >> 8_usize;
        FieldElement::from_be_bytes(&action.to_be_bytes::<32>())
            .expect("a 248-bit value is always below the field modulus")
    }

    /// Returns whether `period_start` is canonical, i.e. 00:00:00 AoE on a month's first day.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        is_canonical_period_start(self.period_start)
    }

    /// Returns whether this context is active at `timestamp` (WIP-107 §4.3).
    #[must_use]
    pub fn is_active_at(&self, timestamp: u64) -> bool {
        is_period_active(self.period_start, timestamp)
    }
}

/// The periods active at a timestamp, as `getActivePeriods` returns them (WIP-107 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivePeriods {
    /// The start of the AoE month containing the timestamp.
    pub current: u64,
    /// The next month's start, while the timestamp is within [`PERIOD_OVERLAP`] of it.
    pub next: Option<u64>,
}

/// The start of the AoE month containing `timestamp`.
///
/// # Errors
/// Fails for a timestamp in a month that starts before the Unix epoch, as the Billing Contract
/// rejects it.
pub fn period_start(timestamp: u64) -> Result<u64, PrimitiveError> {
    let aoe = timestamp
        .checked_sub(AOE_OFFSET)
        .ok_or_else(|| before_epoch(timestamp))?;
    let (year, month, _) = civil_from_days(aoe / SECONDS_PER_DAY);
    Ok(days_from_civil(year, month, 1) * SECONDS_PER_DAY + AOE_OFFSET)
}

/// The start and exclusive end of the AoE month containing `timestamp`, as `getBillingPeriod`
/// returns them.
///
/// # Errors
/// Fails as [`period_start`] does, or if the end does not fit in a `u64`.
pub fn billing_period(timestamp: u64) -> Result<(u64, u64), PrimitiveError> {
    let start = period_start(timestamp)?;
    Ok((start, next_period_start(start)?))
}

/// The periods active at `timestamp`.
///
/// # Errors
/// Fails as [`billing_period`] does.
pub fn active_periods(timestamp: u64) -> Result<ActivePeriods, PrimitiveError> {
    let (current, following) = billing_period(timestamp)?;
    let next = (timestamp.saturating_add(PERIOD_OVERLAP) >= following).then_some(following);
    Ok(ActivePeriods { current, next })
}

/// Returns whether `period_start` is 00:00:00 AoE on a month's first day.
#[must_use]
pub fn is_canonical_period_start(period_start: u64) -> bool {
    self::period_start(period_start).is_ok_and(|start| start == period_start)
}

/// Returns whether the period starting at `period_start` is active at `timestamp`: within
/// `[period_start - PERIOD_OVERLAP, period_end)`. A noncanonical `period_start` is never active.
#[must_use]
pub fn is_period_active(period_start: u64, timestamp: u64) -> bool {
    if !is_canonical_period_start(period_start) {
        return false;
    }
    let Ok(period_end) = next_period_start(period_start) else {
        return false;
    };
    timestamp >= period_start.saturating_sub(PERIOD_OVERLAP) && timestamp < period_end
}

/// The billing OPRF query digest `H_4(DS_QUERY; leaf_index, rp_id, billing_action)`
/// (WIP-107 §4.4.1).
#[must_use]
pub fn billing_query(leaf_index: u64, rp_id: RpId, billing_action: FieldElement) -> FieldElement {
    oprf_query_digest(leaf_index, billing_action, rp_id.into())
}

/// The billing nullifier `H_4(DS_OPRF_PROOF; billing_query, R.x, R.y)`.
///
/// `R` is the unblinded OPRF output of the billing query. The result is the `UniquenessNullifier`
/// of WIP-107 §4.3, and what WIP-202 constraint 7 recomputes.
#[must_use]
pub fn billing_nullifier(
    billing_query: FieldElement,
    oprf_output: ark_babyjubjub::EdwardsAffine,
) -> Nullifier {
    Nullifier::new(poseidon::hash(
        ds::OPRF_PROOF,
        [billing_query, oprf_output.x.into(), oprf_output.y.into()],
    ))
}

/// The start of the AoE month after the one starting at `period_start`.
fn next_period_start(period_start: u64) -> Result<u64, PrimitiveError> {
    let (year, month, _) = civil_from_days((period_start - AOE_OFFSET) / SECONDS_PER_DAY);
    let (year, month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    days_from_civil(year, month, 1)
        .checked_mul(SECONDS_PER_DAY)
        .and_then(|seconds| seconds.checked_add(AOE_OFFSET))
        .ok_or_else(|| PrimitiveError::InvalidInput {
            attribute: "period_start".to_string(),
            reason: "the next period does not fit in a u64".to_string(),
        })
}

fn before_epoch(timestamp: u64) -> PrimitiveError {
    PrimitiveError::InvalidInput {
        attribute: "timestamp".to_string(),
        reason: format!("{timestamp} is in a billing period that starts before the Unix epoch"),
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date, for dates from 1970 on.
///
/// Howard Hinnant's `days_from_civil`, the algorithm Solady's `DateTimeLib` uses.
const fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian date of a day count since 1970-01-01, as `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, the inverse of [`days_from_civil`].
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let days = days + 719_468;
    let era = days / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use ark_ec::AffineRepr;

    // 1 Nov 2026 to 1 Mar 2028, 12:00:00 UTC (00:00:00 AoE).
    const OCT_2026: u64 = 1_790_856_000;
    const NOV_2026: u64 = 1_793_534_400;
    const DEC_2026: u64 = 1_796_126_400;
    const JAN_2027: u64 = 1_798_804_800;
    const FEB_2028: u64 = 1_833_019_200;
    const MAR_2028: u64 = 1_835_524_800;

    fn context(
        chain_id: u64,
        billing_contract: Address,
        rp_id: u64,
        period_start: u64,
    ) -> BillingContext {
        BillingContext {
            chain_id: U256::from(chain_id),
            billing_contract,
            rp_id: RpId::new(rp_id),
            period_start,
        }
    }

    /// Vectors from `cast keccak $(cast abi-encode "f(string,uint256,address,uint64,uint64)" …)`,
    /// i.e. Solidity's `abi.encode`, shifted right by 8 bits.
    #[test]
    fn billing_action_matches_solidity() {
        let action = context(
            480,
            address!("1111111111111111111111111111111111111111"),
            42,
            NOV_2026,
        )
        .billing_action();
        assert_eq!(
            action.to_be_bytes(),
            hex::decode("00c8255a8ab7bc95e92fe237395215679b590a53e2af9f913806cd494fe2c86a")
                .unwrap()
                .as_slice()
        );

        let action = context(
            4801,
            address!("2222222222222222222222222222222222222222"),
            u64::MAX,
            DEC_2026,
        )
        .billing_action();
        assert_eq!(
            action.to_be_bytes(),
            hex::decode("0087e7048876112b44442ce5f227690d1e24de2674ca8135b3c6af1d34dde1a7")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn billing_action_is_a_uniqueness_domain_input() {
        let action = context(480, Address::ZERO, 1, NOV_2026).billing_action();
        assert_eq!(action.to_be_bytes()[0], 0x00);
    }

    #[test]
    fn billing_action_changes_with_every_field() {
        let base = context(480, Address::ZERO, 1, NOV_2026);
        let variants = [
            BillingContext {
                chain_id: U256::from(4801),
                ..base
            },
            BillingContext {
                billing_contract: Address::repeat_byte(1),
                ..base
            },
            BillingContext {
                rp_id: RpId::new(2),
                ..base
            },
            BillingContext {
                period_start: DEC_2026,
                ..base
            },
        ];
        for variant in variants {
            assert_ne!(variant.billing_action(), base.billing_action());
        }
    }

    #[test]
    fn period_start_follows_aoe_months() {
        assert_eq!(period_start(NOV_2026).unwrap(), NOV_2026);
        // 11:59:59 UTC on 1 Nov is still 31 Oct AoE.
        assert_eq!(period_start(NOV_2026 - 1).unwrap(), OCT_2026);
        // 10 Nov 2026, 14:00 UTC.
        assert_eq!(period_start(1_794_319_200).unwrap(), NOV_2026);
        assert_eq!(period_start(43_200).unwrap(), 43_200);
    }

    #[test]
    fn period_start_rejects_months_before_the_epoch() {
        assert!(period_start(0).is_err());
        assert!(period_start(AOE_OFFSET - 1).is_err());
    }

    #[test]
    fn billing_period_rolls_over_years_and_leap_days() {
        assert_eq!(billing_period(NOV_2026).unwrap(), (NOV_2026, DEC_2026));
        assert_eq!(billing_period(DEC_2026 + 1).unwrap(), (DEC_2026, JAN_2027));
        assert_eq!(billing_period(FEB_2028).unwrap(), (FEB_2028, MAR_2028));
        assert_eq!(MAR_2028 - FEB_2028, 29 * SECONDS_PER_DAY);
    }

    #[test]
    fn active_periods_include_the_next_month_within_the_overlap() {
        assert_eq!(
            active_periods(DEC_2026 - PERIOD_OVERLAP - 1).unwrap(),
            ActivePeriods {
                current: NOV_2026,
                next: None
            }
        );
        assert_eq!(
            active_periods(DEC_2026 - PERIOD_OVERLAP).unwrap(),
            ActivePeriods {
                current: NOV_2026,
                next: Some(DEC_2026)
            }
        );
        assert_eq!(
            active_periods(DEC_2026).unwrap(),
            ActivePeriods {
                current: DEC_2026,
                next: None
            }
        );
    }

    #[test]
    fn period_activity_spans_the_overlap_until_the_exclusive_end() {
        assert!(!is_period_active(DEC_2026, DEC_2026 - PERIOD_OVERLAP - 1));
        assert!(is_period_active(DEC_2026, DEC_2026 - PERIOD_OVERLAP));
        assert!(is_period_active(NOV_2026, DEC_2026 - 1));
        assert!(!is_period_active(NOV_2026, DEC_2026));
    }

    #[test]
    fn noncanonical_period_starts_are_rejected() {
        assert!(is_canonical_period_start(NOV_2026));
        assert!(!is_canonical_period_start(NOV_2026 + 1));
        assert!(!is_canonical_period_start(NOV_2026 - AOE_OFFSET));
        assert!(!is_period_active(NOV_2026 + 1, NOV_2026 + 2));
        assert!(!context(480, Address::ZERO, 1, NOV_2026 + 1).is_canonical());
    }

    #[test]
    fn civil_date_conversion_round_trips() {
        for days in [0, 59, 60, 365, 10_957, 11_016, 20_759, 2_932_896] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 29 Feb 2000 and 1 Mar 2000.
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    }

    #[test]
    fn billing_nullifier_finalizes_the_billing_query() {
        let action = context(480, Address::ZERO, 42, NOV_2026).billing_action();
        let query = billing_query(7, RpId::new(42), action);
        assert_eq!(query, oprf_query_digest(7, action, RpId::new(42).into()));

        let output = ark_babyjubjub::EdwardsAffine::generator();
        let nullifier = billing_nullifier(query, output);
        assert_eq!(
            nullifier.inner,
            poseidon::hash(ds::OPRF_PROOF, [query, output.x.into(), output.y.into()])
        );
        assert_ne!(
            billing_nullifier(billing_query(8, RpId::new(42), action), output),
            nullifier
        );
    }
}
