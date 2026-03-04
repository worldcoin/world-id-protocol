#![allow(clippy::unreadable_literal)]

use std::{fmt, str::FromStr};

use ark_ff::{BigInteger as _, PrimeField as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::FieldElement;

const RP_SIGNATURE_MSG_VERSION: u8 = 0x01;

/// The id of a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RpId(u64);

impl RpId {
    /// Converts the RP id to an u64
    #[must_use]
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Creates a new `RpId` by wrapping a `u64`
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rp_{:016x}", self.0)
    }
}

impl FromStr for RpId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(id) = s.strip_prefix("rp_") {
            Ok(Self(u64::from_str_radix(id, 16).map_err(|_| {
                "Invalid RP ID format: expected hex string".to_string()
            })?))
        } else {
            Err("A valid RP ID must start with 'rp_'".to_string())
        }
    }
}

impl From<u64> for RpId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<RpId> for FieldElement {
    fn from(value: RpId) -> Self {
        Self::from(value.0)
    }
}

impl Serialize for RpId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            u64::serialize(&self.0, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RpId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(D::Error::custom)
        } else {
            let value = u64::deserialize(deserializer)?;
            Ok(Self(value))
        }
    }
}

/// Computes the message to be signed for the RP signature.
///
/// The message format is: `version || nonce || created_at || expires_at` (49 bytes total).
/// - `version`: 1 byte (currently hardcoded to `0x01`)
/// - `nonce`: 32 bytes (big-endian)
/// - `created_at`: 8 bytes (big-endian)
/// - `expires_at`: 8 bytes (big-endian)
#[must_use]
pub fn compute_rp_signature_msg(
    nonce: ark_babyjubjub::Fq,
    created_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(49);
    msg.push(RP_SIGNATURE_MSG_VERSION);
    msg.extend(nonce.into_bigint().to_bytes_be());
    msg.extend(created_at.to_be_bytes());
    msg.extend(expires_at.to_be_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpid_display() {
        let rp_id = RpId::new(0x123456789abcdef0);
        assert_eq!(rp_id.to_string(), "rp_123456789abcdef0");

        let rp_id = RpId::new(u64::MAX);
        assert_eq!(rp_id.to_string(), "rp_ffffffffffffffff");

        let rp_id = RpId::new(0);
        assert_eq!(rp_id.to_string(), "rp_0000000000000000");
    }

    #[test]
    fn test_rpid_from_str() {
        let rp_id = "rp_123456789abcdef0".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, 0x123456789abcdef0);

        let rp_id = "rp_ffffffffffffffff".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, u64::MAX);

        let rp_id = "rp_0000000000000000".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, 0);

        let rp_id = "rp_123456789ABCDEF0".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, 0x123456789abcdef0);
    }

    #[test]
    fn test_rpid_from_str_errors() {
        assert!("123456789abcdef0".parse::<RpId>().is_err());
        assert!("rp_invalid".parse::<RpId>().is_err());
        assert!("rp_".parse::<RpId>().is_err());
    }

    #[test]
    fn test_rpid_roundtrip() {
        let original = RpId::new(0x123456789abcdef0);
        let s = original.to_string();
        let parsed = s.parse::<RpId>().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_rpid_json_serialization() {
        let rp_id = RpId::new(0x123456789abcdef0);
        let json = serde_json::to_string(&rp_id).unwrap();
        assert_eq!(json, "\"rp_123456789abcdef0\"");

        let deserialized: RpId = serde_json::from_str(&json).unwrap();
        assert_eq!(rp_id, deserialized);
    }

    #[test]
    fn test_rpid_binary_serialization() {
        let rp_id = RpId::new(0x123456789abcdef0);

        let mut buffer = Vec::new();
        ciborium::into_writer(&rp_id, &mut buffer).unwrap();

        let decoded: RpId = ciborium::from_reader(&buffer[..]).unwrap();

        assert_eq!(rp_id, decoded);
    }

    #[test]
    fn test_compute_rp_signature_msg_fixed_length() {
        // Test with small values that would have leading zeros in variable-length encoding
        // to ensure we always get fixed 32-byte field elements
        let nonce = ark_babyjubjub::Fq::from(1u64);
        let created_at = 1000u64;
        let expires_at = 2000u64;

        let msg = compute_rp_signature_msg(nonce, created_at, expires_at);

        // Message must always be exactly 49 bytes:
        // 1 (version) + 32 (nonce) + 8 (created_at) + 8 (expires_at)
        assert_eq!(
            msg.len(),
            49,
            "RP signature message must be exactly 49 bytes"
        );
        assert_eq!(
            msg[0], RP_SIGNATURE_MSG_VERSION,
            "RP signature message version must be 0x01"
        );
    }
}
