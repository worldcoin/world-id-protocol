//! [`Payment`]: a standalone bearer authorisation for one unit of work on a channel.
//!
//! A `Payment` is not attached to a `ProofRequest` and does not name one. It authorises one
//! unit on one lane counter in one epoch of one channel, and whoever presents it first
//! consumes it. Binding a payment to a particular request is deferred to a later version,
//! which would add the request digest to the signed struct and change nothing else.

use alloy::{
    signers::{Signature, SignerSync},
    sol_types::Eip712Domain,
};
use alloy_primitives::{Address, B256, aliases::U96};
use serde::{Deserialize, Serialize};

use crate::{
    nonce::{LaneNonce, NonceError},
    typed_data::{
        NonceReservation, PaymentAuthorization, RESERVATION_CLOCK_SKEW_SECS, RecoverError,
    },
};

/// Errors raised while signing or verifying a payment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaymentError {
    /// The payment names a different channel.
    #[error("payment names channel {found}, expected {expected}")]
    ChannelMismatch {
        /// The channel expected.
        expected: B256,
        /// The channel the payment names.
        found: B256,
    },
    /// The payment is for a different epoch.
    #[error("payment is for epoch {found}, expected {expected}")]
    EpochMismatch {
        /// The epoch expected.
        expected: u64,
        /// The epoch the payment names.
        found: u64,
    },
    /// The channel nonce is not a usable `(lane, counter)` pair.
    #[error(transparent)]
    Nonce(#[from] NonceError),
    /// The signature is malformed or non-canonical.
    #[error(transparent)]
    Recover(#[from] RecoverError),
    /// The signature recovered to somebody other than the channel's `spendKey`.
    #[error("payment signed by {recovered}, expected spend key {expected}")]
    SignerMismatch {
        /// The channel's pinned `spendKey`.
        expected: Address,
        /// The address the signature recovers to.
        recovered: Address,
    },
    /// The signer failed to produce a signature.
    #[error("signing failed: {0}")]
    Signer(String),
    /// A counter above one was proposed without the RP's signature on the counter below it.
    #[error("no predecessor offered for lane {lane} counter {counter}")]
    MissingPredecessor {
        /// Lane the proposal targets.
        lane: u32,
        /// Counter the proposal targets.
        counter: u64,
    },
    /// A predecessor was offered for counter one, which has none.
    #[error("lane {lane} counter 1 cannot have a predecessor")]
    UnexpectedPredecessor {
        /// Lane the proposal targets.
        lane: u32,
    },
    /// The predecessor is for a different lane or counter.
    #[error("predecessor is {found}, expected {expected}")]
    PredecessorMismatch {
        /// The nonce the predecessor should carry.
        expected: String,
        /// The nonce it actually carries.
        found: String,
    },
}

/// An RP-signed authorisation for one unit of work on a channel.
///
/// `epoch` travels on the wire because a payment names no request, so there is no timestamp to
/// derive it from. A forwarding client must pass the whole object through unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payment {
    /// EIP-712 digest of the channel's settings.
    pub channel_id: B256,
    /// Epoch the reservation was issued for.
    pub epoch: u64,
    /// `lane << 64 | counter`, issued by the collector and verified by the RP.
    #[serde(with = "hex_u96")]
    pub channel_nonce: U96,
    /// `spendKey` signature over the EIP-712 [`PaymentAuthorization`].
    #[serde(with = "world_id_primitives::serde_utils::hex_signature")]
    pub signature: Signature,
}

impl Payment {
    /// Signs the authorisation for `lane_nonce` and wraps it as a payment.
    ///
    /// # Errors
    /// Returns [`PaymentError::Nonce`] for a zero counter and [`PaymentError::Signer`] if the
    /// signer fails.
    pub fn sign<S: SignerSync>(
        channel_id: B256,
        epoch: u64,
        lane_nonce: LaneNonce,
        signer: &S,
        domain: &Eip712Domain,
    ) -> Result<Self, PaymentError> {
        lane_nonce.validate()?;
        let signature = PaymentAuthorization::new(channel_id, epoch, lane_nonce)
            .sign(signer, domain)
            .map_err(|e| PaymentError::Signer(e.to_string()))?;
        Ok(Self {
            channel_id,
            epoch,
            channel_nonce: lane_nonce.pack(),
            signature,
        })
    }

    /// The lane and counter this payment authorises.
    ///
    /// # Errors
    /// Returns [`NonceError::ZeroCounter`] for a zero counter.
    pub fn lane_nonce(&self) -> Result<LaneNonce, NonceError> {
        LaneNonce::unpack(self.channel_nonce)
    }

    /// The signed payload, rebuilt from the wire fields.
    #[must_use]
    pub const fn authorization(&self) -> PaymentAuthorization {
        PaymentAuthorization {
            channelId: self.channel_id,
            epoch: self.epoch,
            channelNonce: self.channel_nonce,
        }
    }

    /// Recovers the signer.
    ///
    /// # Errors
    /// Returns [`PaymentError::Recover`] for a malformed or non-canonical signature.
    pub fn recover(&self, domain: &Eip712Domain) -> Result<Address, PaymentError> {
        Ok(self.authorization().recover(domain, &self.signature)?)
    }

    /// Checks the payment against a channel, an epoch, and a spend key.
    ///
    /// # Errors
    /// See [`PaymentError`].
    pub fn verify(
        &self,
        channel_id: B256,
        epoch: u64,
        spend_key: Address,
        domain: &Eip712Domain,
    ) -> Result<LaneNonce, PaymentError> {
        if self.channel_id != channel_id {
            return Err(PaymentError::ChannelMismatch {
                expected: channel_id,
                found: self.channel_id,
            });
        }
        if self.epoch != epoch {
            return Err(PaymentError::EpochMismatch {
                expected: epoch,
                found: self.epoch,
            });
        }
        let lane_nonce = self.lane_nonce()?;
        let recovered = self.recover(domain)?;
        if recovered != spend_key {
            return Err(PaymentError::SignerMismatch {
                expected: spend_key,
                recovered,
            });
        }
        Ok(lane_nonce)
    }
}

/// The RP's stateless check on a collector's nonce proposal.
///
/// The RP keeps no counter state. It accepts `expected` only if the collector can show the
/// RP's own signature on the counter below it, so the collector can propose `n` only by
/// holding the signature on `n - 1`. Nothing else is checked and nothing is remembered.
///
/// # Errors
/// See [`PaymentError::MissingPredecessor`], [`PaymentError::UnexpectedPredecessor`],
/// [`PaymentError::PredecessorMismatch`], and [`PaymentError::SignerMismatch`].
pub fn verify_predecessor(
    previous: Option<&Payment>,
    channel_id: B256,
    epoch: u64,
    expected: LaneNonce,
    spend_key: Address,
    domain: &Eip712Domain,
) -> Result<(), PaymentError> {
    expected.validate()?;
    let Some(wanted) = expected.predecessor() else {
        return match previous {
            None => Ok(()),
            Some(_) => Err(PaymentError::UnexpectedPredecessor {
                lane: expected.lane,
            }),
        };
    };
    let previous = previous.ok_or(PaymentError::MissingPredecessor {
        lane: expected.lane,
        counter: expected.counter,
    })?;

    let found = previous.verify(channel_id, epoch, spend_key, domain)?;
    if found != wanted {
        return Err(PaymentError::PredecessorMismatch {
            expected: wanted.to_hex(),
            found: found.to_hex(),
        });
    }
    Ok(())
}

/// Serialises a `uint96` strictly as a `0x`-prefixed hex string.
///
/// Stricter than a plain integer on purpose: a channel nonce above 2^53 loses precision in a
/// JSON number, so numbers are refused outright rather than parsed.
mod hex_u96 {
    use alloy_primitives::aliases::U96;
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    /// Hex digits in a `uint96`.
    const MAX_HEX_DIGITS: usize = 24;

    pub(super) fn serialize<S: Serializer>(value: &U96, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U96, D::Error> {
        let s = String::deserialize(deserializer)?;
        let digits = s
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom(format!("expected a 0x-prefixed uint96, got {s:?}")))?;
        if digits.is_empty() {
            return Err(D::Error::custom("no hex digits after the 0x prefix"));
        }
        if digits.len() > MAX_HEX_DIGITS {
            return Err(D::Error::custom(format!(
                "{} hex digits exceeds the {MAX_HEX_DIGITS} of a uint96",
                digits.len()
            )));
        }
        U96::from_str_radix(digits, 16)
            .map_err(|e| D::Error::custom(format!("invalid uint96 {s:?}: {e}")))
    }
}

#[cfg(test)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "shared test helpers for sibling modules"
)]
pub(crate) mod tests {
    use super::*;
    use crate::typed_data::tests::{settings, signer, test_domain};
    use alloy::signers::local::PrivateKeySigner;

    /// The channel every test in the crate pays from.
    pub(crate) fn channel_id(key: &PrivateKeySigner) -> B256 {
        settings(key.address()).channel_id(&test_domain())
    }

    /// A payment for `lane_nonce` in `epoch`, signed by `key`.
    pub(crate) fn paid(key: &PrivateKeySigner, epoch: u64, lane_nonce: LaneNonce) -> Payment {
        Payment::sign(channel_id(key), epoch, lane_nonce, key, &test_domain()).expect("signs")
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = signer(1);
        let payment = paid(&key, 3, LaneNonce::new(1, 2));

        assert_eq!(payment.epoch, 3);
        assert_eq!(payment.channel_nonce, LaneNonce::new(1, 2).pack());
        assert_eq!(
            payment
                .verify(channel_id(&key), 3, key.address(), &test_domain())
                .expect("verifies"),
            LaneNonce::new(1, 2)
        );
    }

    #[test]
    fn a_payment_is_bound_to_one_channel_epoch_and_counter() {
        let key = signer(1);
        let payment = paid(&key, 3, LaneNonce::new(1, 2));
        let domain = test_domain();

        assert!(matches!(
            payment.verify(B256::ZERO, 3, key.address(), &domain),
            Err(PaymentError::ChannelMismatch { .. })
        ));
        assert!(matches!(
            payment.verify(channel_id(&key), 4, key.address(), &domain),
            Err(PaymentError::EpochMismatch {
                expected: 4,
                found: 3
            })
        ));

        // Re-pointing the nonce breaks recovery rather than any field comparison.
        let mut moved = payment;
        moved.channel_nonce = LaneNonce::new(1, 3).pack();
        assert!(matches!(
            moved.verify(channel_id(&key), 3, key.address(), &domain),
            Err(PaymentError::SignerMismatch { .. })
        ));
    }

    #[test]
    fn verify_rejects_a_foreign_spend_key() {
        let key = signer(1);
        let stranger = signer(2);
        let payment = Payment::sign(
            channel_id(&key),
            3,
            LaneNonce::new(0, 1),
            &stranger,
            &test_domain(),
        )
        .expect("signs");

        assert!(matches!(
            payment.verify(channel_id(&key), 3, key.address(), &test_domain()),
            Err(PaymentError::SignerMismatch { .. })
        ));
    }

    #[test]
    fn sign_rejects_a_zero_counter() {
        let key = signer(1);
        assert!(matches!(
            Payment::sign(
                channel_id(&key),
                0,
                LaneNonce::new(0, 0),
                &key,
                &test_domain()
            ),
            Err(PaymentError::Nonce(NonceError::ZeroCounter))
        ));
    }

    #[test]
    fn json_is_the_spec_wire_form() {
        let key = signer(1);
        let payment = paid(&key, 7, LaneNonce::new(3, 42));

        let json = serde_json::to_value(&payment).expect("serialises");
        assert_eq!(json["channel_nonce"], "0x3000000000000002a");
        assert_eq!(json["epoch"], 7, "the epoch is a JSON number");
        assert_eq!(
            json["signature"].as_str().expect("hex").len(),
            132,
            "0x plus 65 bytes"
        );
        assert_eq!(
            serde_json::from_value::<Payment>(json).expect("deserialises"),
            payment
        );
    }

    #[test]
    fn channel_nonce_must_be_a_hex_string_inside_a_uint96() {
        let key = signer(1);
        let mut json = serde_json::to_value(paid(&key, 1, LaneNonce::new(0, 1))).expect("json");

        let mut with = |nonce: serde_json::Value| {
            json["channel_nonce"] = nonce;
            serde_json::from_value::<Payment>(json.clone())
        };
        assert!(with(serde_json::json!("0x1")).is_ok());
        // A number loses precision above 2^53, so it is refused outright.
        assert!(with(serde_json::json!(1)).is_err());
        // 25 hex digits is one more than a uint96 holds.
        assert!(with(serde_json::json!("0x1000000000000000000000000")).is_err());
        assert!(with(serde_json::json!("1")).is_err(), "the 0x prefix");
        assert!(with(serde_json::json!("0x")).is_err());
        assert!(with(serde_json::json!("0xzz")).is_err());
    }

    #[test]
    fn counter_one_needs_no_predecessor() {
        let key = signer(1);
        verify_predecessor(
            None,
            channel_id(&key),
            0,
            LaneNonce::new(0, 1),
            key.address(),
            &test_domain(),
        )
        .expect("counter 1 stands alone");
    }

    #[test]
    fn counter_one_must_not_have_a_predecessor() {
        let key = signer(1);
        let previous = paid(&key, 0, LaneNonce::new(0, 1));
        assert!(matches!(
            verify_predecessor(
                Some(&previous),
                channel_id(&key),
                0,
                LaneNonce::new(0, 1),
                key.address(),
                &test_domain()
            ),
            Err(PaymentError::UnexpectedPredecessor { lane: 0 })
        ));
    }

    #[test]
    fn a_higher_counter_needs_the_rps_own_previous_signature() {
        let key = signer(1);
        let previous = paid(&key, 0, LaneNonce::new(0, 1));
        verify_predecessor(
            Some(&previous),
            channel_id(&key),
            0,
            LaneNonce::new(0, 2),
            key.address(),
            &test_domain(),
        )
        .expect("counter 2 follows counter 1");

        assert!(
            matches!(
                verify_predecessor(
                    None,
                    channel_id(&key),
                    0,
                    LaneNonce::new(0, 2),
                    key.address(),
                    &test_domain()
                ),
                Err(PaymentError::MissingPredecessor {
                    lane: 0,
                    counter: 2
                })
            ),
            "a bare proposal proves nothing"
        );
    }

    #[test]
    fn a_predecessor_from_elsewhere_is_refused() {
        let key = signer(1);
        let stranger = signer(2);
        let domain = test_domain();
        let channel = channel_id(&key);

        // Signed by somebody else.
        let foreign =
            Payment::sign(channel, 0, LaneNonce::new(0, 1), &stranger, &domain).expect("signs");
        assert!(matches!(
            verify_predecessor(
                Some(&foreign),
                channel,
                0,
                LaneNonce::new(0, 2),
                key.address(),
                &domain
            ),
            Err(PaymentError::SignerMismatch { .. })
        ));

        // The RP's own signature, but from another lane.
        let other_lane = paid(&key, 0, LaneNonce::new(1, 1));
        assert!(matches!(
            verify_predecessor(
                Some(&other_lane),
                channel,
                0,
                LaneNonce::new(0, 2),
                key.address(),
                &domain
            ),
            Err(PaymentError::PredecessorMismatch { .. })
        ));

        // The RP's own signature on the right lane, but from another epoch.
        let other_epoch = paid(&key, 1, LaneNonce::new(0, 1));
        assert!(matches!(
            verify_predecessor(
                Some(&other_epoch),
                channel,
                0,
                LaneNonce::new(0, 2),
                key.address(),
                &domain
            ),
            Err(PaymentError::EpochMismatch { .. })
        ));
    }
}

/// Why a collector refused to hold a lane.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReservationError {
    /// The reservation was signed too far from the collector's clock.
    #[error("reservation issued at {issued_at} is more than {skew}s from {now}")]
    Stale {
        /// When the RP says it signed.
        issued_at: u64,
        /// The collector's clock.
        now: u64,
        /// The accepted window, in seconds either side.
        skew: u64,
    },
    /// The signature is malformed or non-canonical.
    #[error(transparent)]
    Recover(#[from] RecoverError),
    /// The signature recovered to somebody other than the channel's `spendKey`.
    #[error("reservation signed by {recovered}, expected spend key {expected}")]
    SignerMismatch {
        /// The channel's pinned `spendKey`.
        expected: Address,
        /// The address the signature recovers to.
        recovered: Address,
    },
}

/// Checks a request to hold a lane.
///
/// A reservation holds capacity for its lifetime, so it is signed: anyone who could send one
/// unsigned could starve the channel that funds it. The freshness window keeps a captured
/// reservation from being replayed later.
///
/// # Errors
/// See [`ReservationError`].
pub fn verify_reservation(
    channel_id: B256,
    epoch: u64,
    issued_at: u64,
    signature: &Signature,
    spend_key: Address,
    domain: &Eip712Domain,
    now: u64,
) -> Result<(), ReservationError> {
    let reservation = NonceReservation::new(channel_id, epoch, issued_at);
    if !reservation.is_fresh(now) {
        return Err(ReservationError::Stale {
            issued_at,
            now,
            skew: RESERVATION_CLOCK_SKEW_SECS,
        });
    }
    let recovered = reservation.recover(domain, signature)?;
    if recovered != spend_key {
        return Err(ReservationError::SignerMismatch {
            expected: spend_key,
            recovered,
        });
    }
    Ok(())
}
