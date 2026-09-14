//! Lane-partitioned channel nonces: `lane << 64 | counter`, packed into the escrow's `uint96`.

use alloy_primitives::aliases::U96;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Hex digits in a `uint96`.
const NONCE_MAX_HEX_DIGITS: usize = 24;

/// Errors produced while packing or parsing channel nonces.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// Counter zero means "no authorisation on this lane" and is never signed.
    #[error("channel nonce counter must be greater than zero")]
    ZeroCounter,
    /// The lane's `u64` counter space is exhausted. Move to a new lane.
    #[error("lane {lane} has no counters left")]
    LaneExhausted {
        /// The exhausted lane.
        lane: u32,
    },
    /// The serialised form was not a `0x`-prefixed hex `uint96`.
    #[error("malformed channel nonce: {0}")]
    Malformed(String),
}

/// A channel nonce: a lane id in the high 32 bits, a per-lane counter in the low 64.
///
/// A counter is cumulative: an authorisation with counter `n` proves `n` units on its lane by
/// itself, whether or not lower counters were ever seen. Serialises as a `0x`-prefixed
/// lowercase hex `uint96`, never a JSON number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneNonce {
    /// Lane id.
    pub lane: u32,
    /// Cumulative per-lane counter, always at least one.
    pub counter: u64,
}

impl LaneNonce {
    /// Creates a lane nonce. A zero counter is rejected by [`Self::validate`] and never packs.
    #[must_use]
    pub const fn new(lane: u32, counter: u64) -> Self {
        Self { lane, counter }
    }

    /// Packs into the escrow's `uint96`, `lane << 64 | counter`.
    #[must_use]
    pub fn pack(self) -> U96 {
        U96::from_limbs([self.counter, u64::from(self.lane)])
    }

    /// Unpacks a `uint96` channel nonce.
    ///
    /// # Errors
    /// Returns [`NonceError::ZeroCounter`] for a zero counter. Every other `uint96` is a
    /// valid `(lane, counter)` pair, so there is no range error to report.
    pub fn unpack(packed: U96) -> Result<Self, NonceError> {
        let [counter, high] = packed.into_limbs();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a uint96's high limb only ever holds 32 significant bits"
        )]
        let nonce = Self {
            lane: high as u32,
            counter,
        };
        nonce.validate()?;
        Ok(nonce)
    }

    /// The nonce one unit earlier on the same lane, or `None` at counter one.
    #[must_use]
    pub const fn predecessor(self) -> Option<Self> {
        match self.counter {
            0 | 1 => None,
            counter => Some(Self::new(self.lane, counter - 1)),
        }
    }

    /// The next nonce on this lane.
    ///
    /// # Errors
    /// Returns [`NonceError::LaneExhausted`] once the lane's counter space runs out.
    pub const fn successor(self) -> Result<Self, NonceError> {
        match self.counter.checked_add(1) {
            Some(counter) => Ok(Self::new(self.lane, counter)),
            None => Err(NonceError::LaneExhausted { lane: self.lane }),
        }
    }

    /// Rejects a zero counter.
    ///
    /// # Errors
    /// Returns [`NonceError::ZeroCounter`].
    pub const fn validate(&self) -> Result<(), NonceError> {
        if self.counter == 0 {
            return Err(NonceError::ZeroCounter);
        }
        Ok(())
    }

    /// Renders the `0x`-prefixed lowercase hex `uint96`.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:#x}", self.pack())
    }

    /// Parses a `0x`-prefixed hex `uint96`.
    ///
    /// # Errors
    /// Returns [`NonceError::Malformed`] for a missing prefix, empty body, non-hex digits, or
    /// more than 24 digits, and [`NonceError::ZeroCounter`] for a zero counter.
    pub fn from_hex(s: &str) -> Result<Self, NonceError> {
        let digits = s
            .strip_prefix("0x")
            .ok_or_else(|| NonceError::Malformed(format!("expected a 0x prefix, got {s:?}")))?;
        if digits.is_empty() {
            return Err(NonceError::Malformed("no hex digits".to_string()));
        }
        if digits.len() > NONCE_MAX_HEX_DIGITS {
            return Err(NonceError::Malformed(format!(
                "{} hex digits exceeds the {NONCE_MAX_HEX_DIGITS} of a uint96",
                digits.len()
            )));
        }
        let packed = U96::from_str_radix(digits, 16)
            .map_err(|e| NonceError::Malformed(format!("{s:?}: {e}")))?;
        Self::unpack(packed)
    }
}

impl Serialize for LaneNonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for LaneNonce {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        for nonce in [
            LaneNonce::new(0, 1),
            LaneNonce::new(1, u64::MAX),
            LaneNonce::new(u32::MAX, 1),
            LaneNonce::new(u32::MAX, u64::MAX),
        ] {
            assert_eq!(LaneNonce::unpack(nonce.pack()).expect("unpacks"), nonce);
        }
        assert_eq!(
            LaneNonce::new(3, 5).pack(),
            U96::from((3u128 << 64) | 5),
            "lane << 64 | counter"
        );
    }

    #[test]
    fn a_zero_counter_is_never_a_nonce() {
        assert_eq!(LaneNonce::unpack(U96::ZERO), Err(NonceError::ZeroCounter));
        assert_eq!(
            LaneNonce::unpack(U96::from(1u128 << 64)),
            Err(NonceError::ZeroCounter),
            "lane 1 with a zero counter is still a zero counter"
        );
        assert_eq!(
            LaneNonce::new(0, 0).validate(),
            Err(NonceError::ZeroCounter)
        );
    }

    #[test]
    fn predecessor_and_successor_walk_one_lane() {
        assert_eq!(LaneNonce::new(2, 1).predecessor(), None);
        assert_eq!(
            LaneNonce::new(2, 5).predecessor(),
            Some(LaneNonce::new(2, 4))
        );
        assert_eq!(
            LaneNonce::new(2, 5).successor(),
            Ok(LaneNonce::new(2, 6)),
            "counters never wrap"
        );
        assert_eq!(
            LaneNonce::new(2, u64::MAX).successor(),
            Err(NonceError::LaneExhausted { lane: 2 })
        );
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(LaneNonce::new(1, 5).to_hex(), "0x10000000000000005");
        assert_eq!(
            LaneNonce::from_hex("0x10000000000000005").expect("parses"),
            LaneNonce::new(1, 5)
        );
        assert_eq!(LaneNonce::new(0, 1).to_hex(), "0x1");
    }

    #[test]
    fn hex_rejects_malformed_and_oversized() {
        for bad in ["10", "0x", "0xzz", "0x1000000000000000000000000"] {
            assert!(
                matches!(LaneNonce::from_hex(bad), Err(NonceError::Malformed(_))),
                "{bad} must be refused"
            );
        }
        // The widest valid nonce: lane u32::MAX, counter 1.
        assert_eq!(
            LaneNonce::from_hex("0xffffffff0000000000000001").expect("parses"),
            LaneNonce::new(u32::MAX, 1)
        );
        assert_eq!(
            LaneNonce::from_hex("0xffffffff0000000000000000"),
            Err(NonceError::ZeroCounter),
            "24 digits but a zero counter"
        );
    }

    #[test]
    fn serde_is_a_hex_string_and_never_a_number() {
        let nonce = LaneNonce::new(2, 9);
        let json = serde_json::to_string(&nonce).expect("serialises");
        assert_eq!(json, "\"0x20000000000000009\"");
        assert_eq!(
            serde_json::from_str::<LaneNonce>(&json).expect("deserialises"),
            nonce
        );
        assert!(serde_json::from_str::<LaneNonce>("\"0x0\"").is_err());
        assert!(serde_json::from_str::<LaneNonce>("5").is_err());
    }
}
