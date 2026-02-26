//! Serialization utilities for numeric API values across the protocol.
//!
//! Convention used by helpers in this module:
//! - serialization always emits `0x`-prefixed hex strings;
//! - deserialization accepts either decimal (no prefix) or hex (`0x`/`0X` prefix).

#![allow(clippy::missing_errors_doc)]

use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

fn parse_radix_and_digits(input: &str) -> Result<(u64, &str), String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty numeric string".to_string());
    }

    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if rest.is_empty() {
            return Err("missing digits after 0x prefix".to_string());
        }
        Ok((16, rest))
    } else {
        Ok((10, s))
    }
}

/// Serialize as `0x`-prefixed hex and deserialize from decimal or `0x`/`0X` hex.
pub mod hex_u256 {
    use super::*;

    /// Serialize a `U256` as a `0x`-prefixed hex string.
    pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    /// Deserialize a `U256` from a numeric string.
    ///
    /// `0x`/`0X`-prefixed values are parsed as hex, while unprefixed values are parsed as decimal.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let (radix, digits) = parse_radix_and_digits(&s).map_err(D::Error::custom)?;
        U256::from_str_radix(digits, radix)
            .map_err(|e| D::Error::custom(format!("invalid numeric U256: {e}")))
    }
}

/// Serialize as optional `0x`-prefixed hex and deserialize from decimal or `0x`/`0X` hex.
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

    /// Deserialize an `Option<U256>` from an optional numeric string.
    ///
    /// `0x`/`0X`-prefixed values are parsed as hex, while unprefixed values are parsed as decimal.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let (radix, digits) = parse_radix_and_digits(&s).map_err(D::Error::custom)?;
                let v = U256::from_str_radix(digits, radix)
                    .map_err(|e| D::Error::custom(format!("invalid numeric U256: {e}")))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }
}

/// Serialize as `0x`-prefixed hex strings and deserialize from decimal or `0x`/`0X` hex.
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

    /// Deserialize a `Vec<U256>` from a vector of numeric strings.
    ///
    /// `0x`/`0X`-prefixed values are parsed as hex, while unprefixed values are parsed as decimal.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let (radix, digits) = parse_radix_and_digits(&s).map_err(D::Error::custom)?;
                U256::from_str_radix(digits, radix)
                    .map_err(|e| D::Error::custom(format!("invalid numeric U256: {e}")))
            })
            .collect()
    }
}

/// Serialize as optional `0x`-prefixed hex strings and deserialize from decimal or `0x`/`0X` hex.
pub mod hex_u256_opt_vec {
    use super::*;

    /// Serialize a `Vec<Option<U256>>` as a vector of optional `0x`-prefixed hex strings.
    pub fn serialize<S>(values: &[Option<U256>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_strings: Vec<Option<String>> = values
            .iter()
            .map(|value| value.as_ref().map(|v| format!("{v:#x}")))
            .collect();
        hex_strings.serialize(serializer)
    }

    /// Deserialize a `Vec<Option<U256>>` from a vector of optional numeric strings.
    ///
    /// `0x`/`0X`-prefixed values are parsed as hex, while unprefixed values are parsed as decimal.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Option<U256>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<Option<String>> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|value| match value {
                Some(s) => {
                    let (radix, digits) = parse_radix_and_digits(&s).map_err(D::Error::custom)?;
                    U256::from_str_radix(digits, radix)
                        .map(Some)
                        .map_err(|e| D::Error::custom(format!("invalid numeric U256: {e}")))
                }
                None => Ok(None),
            })
            .collect()
    }
}

/// Serialize as `0x`-prefixed hex and deserialize from decimal or `0x`/`0X` hex.
pub mod hex_u64 {
    use super::*;

    /// Serialize a `u64` as a `0x`-prefixed hex string.
    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    /// Deserialize a `u64` from a numeric string.
    ///
    /// `0x`/`0X`-prefixed values are parsed as hex, while unprefixed values are parsed as decimal.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let (radix, digits) = parse_radix_and_digits(&s).map_err(D::Error::custom)?;
        u64::from_str_radix(digits, radix as u32)
            .map_err(|e| D::Error::custom(format!("invalid numeric u64: {e}")))
    }
}

/// Serialize as `0x`-prefixed hex and deserialize from decimal or `0x`/`0X` hex.
pub mod hex_u32 {
    use super::*;

    /// Serialize a `u32` as a `0x`-prefixed hex string.
    pub fn serialize<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    /// Deserialize a `u32` from a numeric string.
    ///
    /// `0x`/`0X`-prefixed values are parsed as hex, while unprefixed values are parsed as decimal.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let (radix, digits) = parse_radix_and_digits(&s).map_err(D::Error::custom)?;
        u32::from_str_radix(digits, radix as u32)
            .map_err(|e| D::Error::custom(format!("invalid numeric u32: {e}")))
    }
}

/// Serialize as optional `0x`-prefixed hex and deserialize from decimal or `0x`/`0X` hex.
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

    /// Deserialize an `Option<u32>` from an optional numeric string.
    ///
    /// `0x`/`0X`-prefixed values are parsed as hex, while unprefixed values are parsed as decimal.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let (radix, digits) = parse_radix_and_digits(&s).map_err(D::Error::custom)?;
                let v = u32::from_str_radix(digits, radix as u32)
                    .map_err(|e| D::Error::custom(format!("invalid numeric u32: {e}")))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }
}

/// Serialize an `alloy_primitives::Signature` as a `0x`-prefixed hex string (65 bytes: `r || s || v`).
pub mod hex_signature {
    use alloy_primitives::Signature;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
    use std::str::FromStr;

    /// Serialize a `Signature` as a `0x`-prefixed hex string.
    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&sig.to_string())
    }

    /// Deserialize a `Signature` from a `0x`-prefixed hex string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_str(&s).map_err(D::Error::custom)
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

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestOptVec {
        #[serde(with = "hex_u256_opt_vec")]
        values: Vec<Option<U256>>,
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

    #[test]
    fn test_deserialize_decimal_without_prefix() {
        let parsed: Test = serde_json::from_str(r#"{"u256_val":"42","u64_val":"42"}"#).unwrap();
        assert_eq!(parsed.u256_val, U256::from(42));
        assert_eq!(parsed.u64_val, 42);
    }

    #[test]
    fn test_deserialize_hex_with_prefix() {
        let parsed: Test = serde_json::from_str(r#"{"u256_val":"0x2a","u64_val":"0x2a"}"#).unwrap();
        assert_eq!(parsed.u256_val, U256::from(42));
        assert_eq!(parsed.u64_val, 42);
    }

    #[test]
    fn test_unprefixed_hex_like_value_is_rejected() {
        let err = serde_json::from_str::<Test>(r#"{"u256_val":"ff","u64_val":"255"}"#).unwrap_err();
        assert!(err.to_string().contains("invalid numeric U256"));
    }

    #[test]
    fn test_u256_opt_vec_roundtrip() {
        let original = TestOptVec {
            values: vec![Some(U256::from(1)), None, Some(U256::from(255))],
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"values":["0x1",null,"0xff"]}"#);

        let parsed: TestOptVec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_u256_opt_vec_deserialize_decimal_and_null() {
        let parsed: TestOptVec = serde_json::from_str(r#"{"values":["42",null,"0x2a"]}"#).unwrap();
        assert_eq!(
            parsed.values,
            vec![Some(U256::from(42)), None, Some(U256::from(42))]
        );
    }
}
