//! Serialization utilities for consistent hex encoding across the protocol.
//!
//! This module provides serde helpers for serializing numeric types as `0x`-prefixed
//! hex strings, which is the standard format in the Ethereum ecosystem.

#![allow(clippy::missing_errors_doc)]

use ruint::aliases::U256;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

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
    struct TestU256 {
        #[serde(with = "hex_u256")]
        value: U256,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestU256Opt {
        #[serde(with = "hex_u256_opt")]
        value: Option<U256>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestU256Vec {
        #[serde(with = "hex_u256_vec")]
        values: Vec<U256>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestU64 {
        #[serde(with = "hex_u64")]
        value: u64,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestU32 {
        #[serde(with = "hex_u32")]
        value: u32,
    }

    #[test]
    fn test_hex_u256_serialize() {
        let test = TestU256 {
            value: U256::from(255u64),
        };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(json, r#"{"value":"0xff"}"#);
    }

    #[test]
    fn test_hex_u256_deserialize_with_prefix() {
        let json = r#"{"value":"0xff"}"#;
        let test: TestU256 = serde_json::from_str(json).unwrap();
        assert_eq!(test.value, U256::from(255u64));
    }

    #[test]
    fn test_hex_u256_deserialize_without_prefix() {
        let json = r#"{"value":"ff"}"#;
        let test: TestU256 = serde_json::from_str(json).unwrap();
        assert_eq!(test.value, U256::from(255u64));
    }

    #[test]
    fn test_hex_u256_large_value() {
        let test = TestU256 {
            value: U256::from_str_radix(
                "11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2",
                16,
            )
            .unwrap(),
        };
        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2"));

        let roundtrip: TestU256 = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, test);
    }

    #[test]
    fn test_hex_u256_opt_some() {
        let test = TestU256Opt {
            value: Some(U256::from(42u64)),
        };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(json, r#"{"value":"0x2a"}"#);

        let roundtrip: TestU256Opt = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, test);
    }

    #[test]
    fn test_hex_u256_opt_none() {
        let test = TestU256Opt { value: None };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(json, r#"{"value":null}"#);

        let roundtrip: TestU256Opt = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, test);
    }

    #[test]
    fn test_hex_u256_vec() {
        let test = TestU256Vec {
            values: vec![U256::from(1u64), U256::from(255u64), U256::from(4096u64)],
        };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(json, r#"{"values":["0x1","0xff","0x1000"]}"#);

        let roundtrip: TestU256Vec = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, test);
    }

    #[test]
    fn test_hex_u64_serialize() {
        let test = TestU64 { value: 255 };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(json, r#"{"value":"0xff"}"#);
    }

    #[test]
    fn test_hex_u64_deserialize() {
        let json = r#"{"value":"0x2a"}"#;
        let test: TestU64 = serde_json::from_str(json).unwrap();
        assert_eq!(test.value, 42);
    }

    #[test]
    fn test_hex_u32_serialize() {
        let test = TestU32 { value: 255 };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(json, r#"{"value":"0xff"}"#);
    }

    #[test]
    fn test_hex_u32_deserialize() {
        let json = r#"{"value":"0x2a"}"#;
        let test: TestU32 = serde_json::from_str(json).unwrap();
        assert_eq!(test.value, 42);
    }
}
