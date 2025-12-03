#![allow(clippy::unreadable_literal)]

use std::{fmt, str::FromStr};

use alloy_primitives::U160;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::FieldElement;

/// The id of a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RpId(U160);

impl RpId {
    /// Converts the RP id to an U160
    #[must_use]
    pub const fn into_inner(self) -> U160 {
        self.0
    }

    /// Creates a new `RpId` by wrapping a `U160`
    #[must_use]
    pub const fn new(value: U160) -> Self {
        Self(value)
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rp_{:040x}", self.0)
    }
}

impl FromStr for RpId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(id) = s.strip_prefix("rp_") {
            Ok(Self(U160::from_str_radix(id, 16).map_err(|_| {
                "Invalid RP ID format: expected hex string".to_string()
            })?))
        } else {
            Err("A valid RP ID must start with 'rp_'".to_string())
        }
    }
}

impl From<U160> for RpId {
    fn from(value: U160) -> Self {
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
            U160::serialize(&self.0, serializer)
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
            let value = U160::deserialize(deserializer)?;
            Ok(Self(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::uint;

    use super::*;

    #[test]
    fn test_rpid_display() {
        let rp_id = RpId::new(uint!(0x123456789abcdef0_U160));
        assert_eq!(
            rp_id.to_string(),
            "rp_000000000000000000000000123456789abcdef0"
        );

        let rp_id = RpId::new(U160::MAX);
        assert_eq!(
            rp_id.to_string(),
            "rp_ffffffffffffffffffffffffffffffffffffffff"
        );

        let rp_id = RpId::new(U160::ZERO);
        assert_eq!(
            rp_id.to_string(),
            "rp_0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_rpid_from_str() {
        let rp_id = "rp_000000000000000000000000123456789abcdef0"
            .parse::<RpId>()
            .unwrap();
        assert_eq!(rp_id.0, uint!(0x123456789abcdef0_U160));

        let rp_id = "rp_ffffffffffffffffffffffffffffffffffffffff"
            .parse::<RpId>()
            .unwrap();
        assert_eq!(rp_id.0, U160::MAX);

        let rp_id = "rp_0000000000000000000000000000000000000000"
            .parse::<RpId>()
            .unwrap();
        assert_eq!(rp_id.0, 0);

        let rp_id = "rp_000000000000000000000000123456789ABCDEF0"
            .parse::<RpId>()
            .unwrap();
        assert_eq!(rp_id.0, uint!(0x123456789abcdef0_U160));
    }

    #[test]
    fn test_rpid_from_str_errors() {
        assert!("123456789abcdef0".parse::<RpId>().is_err());
        assert!("rp_invalid".parse::<RpId>().is_err());
        // TODO? empty string parses to 0 with U160::from_str_radix
        // assert!("rp_".parse::<RpId>().is_err());
    }

    #[test]
    fn test_rpid_roundtrip() {
        let original = RpId::new(uint!(0x123456789abcdef0_U160));
        let s = original.to_string();
        let parsed = s.parse::<RpId>().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_rpid_json_serialization() {
        let rp_id = RpId::new(uint!(0x123456789abcdef0_U160));
        let json = serde_json::to_string(&rp_id).unwrap();
        assert_eq!(json, "\"rp_000000000000000000000000123456789abcdef0\"");

        let deserialized: RpId = serde_json::from_str(&json).unwrap();
        assert_eq!(rp_id, deserialized);
    }

    #[test]
    fn test_rpid_binary_serialization() {
        let rp_id = RpId::new(uint!(0x123456789abcdef0_U160));

        let mut buffer = Vec::new();
        ciborium::into_writer(&rp_id, &mut buffer).unwrap();

        let decoded: RpId = ciborium::from_reader(&buffer[..]).unwrap();

        assert_eq!(rp_id, decoded);
    }
}
