//! Lane-partitioned channel nonces and the RP-side allocator that hands them out.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Number of bits the escrow reserves for a packed channel nonce (`uint96`).
const NONCE_BITS: u32 = 96;
/// Upper bound (exclusive) of a packed channel nonce.
const NONCE_MAX_EXCLUSIVE: u128 = 1u128 << NONCE_BITS;
/// Maximum number of hex digits in a `uint96`.
const NONCE_MAX_HEX_DIGITS: usize = 24;

/// Errors produced while packing, parsing, or allocating channel nonces.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// The packed value does not fit in the escrow's `uint96`.
    #[error("channel nonce {0:#x} does not fit in 96 bits")]
    TooLarge(u128),
    /// Counter zero is reserved as "no authorisation seen" by the escrow.
    #[error("channel nonce counter must be greater than zero")]
    ZeroCounter,
    /// Lane id is outside `[0, lane_count)`.
    #[error("lane {lane} is out of range for a channel with {lane_count} lane(s)")]
    InvalidLane {
        /// The requested lane.
        lane: u32,
        /// The channel's configured lane count.
        lane_count: u32,
    },
    /// A channel must have at least one lane.
    #[error("a channel must have at least one lane")]
    ZeroLaneCount,
    /// The lane's `u64` counter space is exhausted.
    #[error("lane {lane} has no counters left")]
    LaneExhausted {
        /// The exhausted lane.
        lane: u32,
    },
    /// The serialised form was not a `0x`-prefixed hex `uint96`.
    #[error("malformed channel nonce: {0}")]
    Malformed(String),
}

/// A channel nonce: a lane id in the high 32 bits and a per-lane counter in the low 64.
///
/// Serialises as a `0x`-prefixed lowercase hex `uint96`, the form the escrow ABI expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneNonce {
    /// Lane id, must be `< ChannelSettings.laneCount`.
    pub lane: u32,
    /// Strictly increasing per-lane counter, must be non-zero.
    pub counter: u64,
}

impl LaneNonce {
    /// Creates a lane nonce without validating it against a channel.
    #[must_use]
    pub const fn new(lane: u32, counter: u64) -> Self {
        Self { lane, counter }
    }

    /// Packs into the escrow's `uint96` representation, `lane << 64 | counter`.
    #[must_use]
    pub fn pack(self) -> u128 {
        (u128::from(self.lane) << 64) | u128::from(self.counter)
    }

    /// Unpacks a `uint96` channel nonce.
    ///
    /// # Errors
    /// Returns [`NonceError::TooLarge`] above 96 bits and [`NonceError::ZeroCounter`] for a
    /// zero counter.
    pub fn unpack(packed: u128) -> Result<Self, NonceError> {
        if packed >= NONCE_MAX_EXCLUSIVE {
            return Err(NonceError::TooLarge(packed));
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "both halves are masked/shifted into range by the 96-bit check above"
        )]
        let nonce = Self {
            lane: (packed >> 64) as u32,
            counter: (packed & u128::from(u64::MAX)) as u64,
        };
        if nonce.counter == 0 {
            return Err(NonceError::ZeroCounter);
        }
        Ok(nonce)
    }

    /// Checks the nonce against a channel's lane count.
    ///
    /// # Errors
    /// Returns [`NonceError::InvalidLane`] or [`NonceError::ZeroCounter`].
    pub const fn validate(&self, lane_count: u32) -> Result<(), NonceError> {
        if self.lane >= lane_count {
            return Err(NonceError::InvalidLane {
                lane: self.lane,
                lane_count,
            });
        }
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

    /// Parses the `0x`-prefixed lowercase hex `uint96`.
    ///
    /// # Errors
    /// Returns [`NonceError::Malformed`] for a missing prefix, empty body, or non-hex digits,
    /// and [`NonceError::TooLarge`] / [`NonceError::ZeroCounter`] for out-of-range values.
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
        if digits
            .chars()
            .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
        {
            return Err(NonceError::Malformed(format!(
                "expected lowercase hex digits, got {s:?}"
            )));
        }
        let packed = u128::from_str_radix(digits, 16)
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

/// RP-side allocator handing out monotonic counters per lane.
///
/// In-memory only. A real RP must persist `next` before releasing a signed request, or it
/// will re-sign a counter the collector has already banked and the escrow will reject it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceAllocator {
    lane_count: u32,
    /// Next counter to hand out per lane; starts at 1 because zero is reserved.
    next: Vec<u64>,
    cursor: u32,
}

impl NonceAllocator {
    /// Creates an allocator for a channel with `lane_count` lanes.
    ///
    /// # Errors
    /// Returns [`NonceError::ZeroLaneCount`] if `lane_count` is zero.
    pub fn new(lane_count: u32) -> Result<Self, NonceError> {
        if lane_count == 0 {
            return Err(NonceError::ZeroLaneCount);
        }
        Ok(Self {
            lane_count,
            next: vec![1; lane_count as usize],
            cursor: 0,
        })
    }

    /// Number of lanes this allocator serves.
    #[must_use]
    pub const fn lane_count(&self) -> u32 {
        self.lane_count
    }

    /// Allocates the next counter on `lane`.
    ///
    /// # Errors
    /// Returns [`NonceError::InvalidLane`] for an unknown lane and
    /// [`NonceError::LaneExhausted`] once the lane's counter space runs out.
    pub fn next(&mut self, lane: u32) -> Result<LaneNonce, NonceError> {
        let slot = self
            .next
            .get_mut(lane as usize)
            .ok_or(NonceError::InvalidLane {
                lane,
                lane_count: self.lane_count,
            })?;
        let counter = *slot;
        *slot = counter
            .checked_add(1)
            .ok_or(NonceError::LaneExhausted { lane })?;
        Ok(LaneNonce::new(lane, counter))
    }

    /// Allocates from the next lane in round-robin order.
    ///
    /// # Errors
    /// Returns [`NonceError::LaneExhausted`] once the chosen lane's counter space runs out.
    pub fn next_round_robin(&mut self) -> Result<LaneNonce, NonceError> {
        let lane = self.cursor;
        self.cursor = (self.cursor + 1) % self.lane_count;
        self.next(lane)
    }

    /// Highest counter handed out on `lane`, or zero for an unknown or untouched lane.
    #[must_use]
    pub fn high_water(&self, lane: u32) -> u64 {
        self.next
            .get(lane as usize)
            .map_or(0, |next| next.saturating_sub(1))
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
            assert_eq!(LaneNonce::unpack(nonce.pack()).unwrap(), nonce);
        }
        assert_eq!(LaneNonce::new(3, 5).pack(), (3u128 << 64) | 5);
    }

    #[test]
    fn unpack_rejects_out_of_range() {
        assert_eq!(
            LaneNonce::unpack(1u128 << 96),
            Err(NonceError::TooLarge(1u128 << 96))
        );
        assert_eq!(LaneNonce::unpack(0), Err(NonceError::ZeroCounter));
        assert_eq!(
            LaneNonce::unpack(1u128 << 64),
            Err(NonceError::ZeroCounter),
            "lane 1 with a zero counter is still a zero counter"
        );
    }

    #[test]
    fn validate_checks_lane_bounds() {
        assert!(LaneNonce::new(1, 1).validate(2).is_ok());
        assert_eq!(
            LaneNonce::new(2, 1).validate(2),
            Err(NonceError::InvalidLane {
                lane: 2,
                lane_count: 2
            })
        );
        assert_eq!(
            LaneNonce::new(0, 0).validate(2),
            Err(NonceError::ZeroCounter)
        );
    }

    #[test]
    fn hex_roundtrip() {
        let nonce = LaneNonce::new(1, 5);
        assert_eq!(nonce.to_hex(), "0x10000000000000005");
        assert_eq!(LaneNonce::from_hex("0x10000000000000005").unwrap(), nonce);
        assert_eq!(LaneNonce::new(0, 1).to_hex(), "0x1");
    }

    #[test]
    fn hex_rejects_malformed_and_oversized() {
        assert!(matches!(
            LaneNonce::from_hex("10"),
            Err(NonceError::Malformed(_))
        ));
        assert!(matches!(
            LaneNonce::from_hex("0x"),
            Err(NonceError::Malformed(_))
        ));
        assert!(matches!(
            LaneNonce::from_hex("0xzz"),
            Err(NonceError::Malformed(_))
        ));
        // Uppercase is rejected so the wire form stays canonical.
        assert!(matches!(
            LaneNonce::from_hex("0xAB"),
            Err(NonceError::Malformed(_))
        ));
        // 25 digits: one more than a uint96 holds.
        assert!(matches!(
            LaneNonce::from_hex("0x1000000000000000000000000"),
            Err(NonceError::Malformed(_))
        ));
        // The widest valid nonce: lane u32::MAX, counter 1.
        assert_eq!(
            LaneNonce::from_hex("0xffffffff0000000000000001").unwrap(),
            LaneNonce::new(u32::MAX, 1)
        );
        // 24 digits but a zero counter.
        assert_eq!(
            LaneNonce::from_hex("0xffffffff0000000000000000"),
            Err(NonceError::ZeroCounter)
        );
    }

    #[test]
    fn serde_roundtrip_is_a_hex_string() {
        let nonce = LaneNonce::new(2, 9);
        let json = serde_json::to_string(&nonce).unwrap();
        assert_eq!(json, "\"0x20000000000000009\"");
        assert_eq!(
            serde_json::from_str::<LaneNonce>(&json).unwrap(),
            nonce,
            "roundtrip"
        );
        assert!(serde_json::from_str::<LaneNonce>("\"0x0\"").is_err());
        assert!(serde_json::from_str::<LaneNonce>("5").is_err());
    }

    #[test]
    fn allocator_is_monotonic_per_lane() {
        let mut alloc = NonceAllocator::new(2).unwrap();
        assert_eq!(alloc.next(0).unwrap(), LaneNonce::new(0, 1));
        assert_eq!(alloc.next(0).unwrap(), LaneNonce::new(0, 2));
        assert_eq!(alloc.next(1).unwrap(), LaneNonce::new(1, 1));
        assert_eq!(alloc.high_water(0), 2);
        assert_eq!(alloc.high_water(1), 1);
        assert_eq!(
            alloc.next(2),
            Err(NonceError::InvalidLane {
                lane: 2,
                lane_count: 2
            })
        );
    }

    #[test]
    fn round_robin_cycles_lanes() {
        let mut alloc = NonceAllocator::new(2).unwrap();
        let issued: Vec<_> = (0..5).map(|_| alloc.next_round_robin().unwrap()).collect();
        assert_eq!(
            issued,
            vec![
                LaneNonce::new(0, 1),
                LaneNonce::new(1, 1),
                LaneNonce::new(0, 2),
                LaneNonce::new(1, 2),
                LaneNonce::new(0, 3),
            ]
        );
    }

    #[test]
    fn allocator_rejects_zero_lanes() {
        assert_eq!(NonceAllocator::new(0), Err(NonceError::ZeroLaneCount));
    }

    #[test]
    fn lane_exhaustion_is_reported() {
        let mut alloc = NonceAllocator::new(1).unwrap();
        alloc.next[0] = u64::MAX - 1;
        assert_eq!(alloc.next(0).unwrap(), LaneNonce::new(0, u64::MAX - 1));
        assert_eq!(alloc.next(0), Err(NonceError::LaneExhausted { lane: 0 }));
    }
}
