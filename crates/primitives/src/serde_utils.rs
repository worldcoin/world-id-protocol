//! Serialization utilities for consistent hex encoding across the protocol.

#![allow(clippy::missing_errors_doc)]

use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Serialize/deserialize `U256` as a `0x`-prefixed hex string.
pub mod hex_u256 {
    use super::*;

    /// Serialize a `U256` as a `0x`-prefixed hex string.
    pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    /// Deserialize a `U256` from a hex string (with or without `0x` prefix).
    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.trim_start_matches("0x");
        U256::from_str_radix(s, 16).map_err(|e| D::Error::custom(format!("invalid hex U256: {e}")))
    }
}

/// Serialize/deserialize `Option<U256>` as an optional `0x`-prefixed hex string.
pub mod hex_u256_opt {
    use super::*;

    /// Serialize an `Option<U256>` as an optional `0x`-prefixed hex string.
    pub fn serialize<S>(value: &Option<U256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.serialize_some(&format!("{v:#x}")),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize an `Option<U256>` from an optional hex string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.trim_start_matches("0x");
                let v = U256::from_str_radix(s, 16)
                    .map_err(|e| D::Error::custom(format!("invalid hex U256: {e}")))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }
}

/// Serialize/deserialize `Vec<U256>` as a vector of `0x`-prefixed hex strings.
pub mod hex_u256_vec {
    use super::*;

    /// Serialize a `Vec<U256>` as a vector of `0x`-prefixed hex strings.
    pub fn serialize<S>(values: &[U256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_strings: Vec<String> = values.iter().map(|v| format!("{v:#x}")).collect();
        hex_strings.serialize(serializer)
    }

    /// Deserialize a `Vec<U256>` from a vector of hex strings.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let s = s.trim_start_matches("0x");
                U256::from_str_radix(s, 16)
                    .map_err(|e| D::Error::custom(format!("invalid hex U256: {e}")))
            })
            .collect()
    }
}

/// Serialize/deserialize `u64` as a `0x`-prefixed hex string.
pub mod hex_u64 {
    use super::*;

    /// Serialize a `u64` as a `0x`-prefixed hex string.
    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    /// Deserialize a `u64` from a hex string (with or without `0x` prefix).
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.trim_start_matches("0x");
        u64::from_str_radix(s, 16).map_err(|e| D::Error::custom(format!("invalid hex u64: {e}")))
    }
}

/// Serialize/deserialize `u32` as a `0x`-prefixed hex string.
pub mod hex_u32 {
    use super::*;

    /// Serialize a `u32` as a `0x`-prefixed hex string.
    pub fn serialize<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    /// Deserialize a `u32` from a hex string (with or without `0x` prefix).
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.trim_start_matches("0x");
        u32::from_str_radix(s, 16).map_err(|e| D::Error::custom(format!("invalid hex u32: {e}")))
    }
}

/// Serialize/deserialize `Option<u32>` as an optional `0x`-prefixed hex string.
pub mod hex_u32_opt {
    use super::*;

    /// Serialize an `Option<u32>` as an optional `0x`-prefixed hex string.
    pub fn serialize<S>(value: &Option<u32>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.serialize_some(&format!("{v:#x}")),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize an `Option<u32>` from an optional hex string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.trim_start_matches("0x");
                let v = u32::from_str_radix(s, 16)
                    .map_err(|e| D::Error::custom(format!("invalid hex u32: {e}")))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Test {
        #[serde(with = "hex_u256")]
        u256_val: U256,
        #[serde(with = "hex_u64")]
        u64_val: u64,
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = Test {
            u256_val: U256::from(0xdead_beef_u64),
            u64_val: 42,
        };
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("0xdeadbeef"));
        assert!(json.contains("0x2a"));

        let parsed: Test = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }
}
