//! Introduces low level primitives for interacting with the World ID Protocol.

use ark_babyjubjub::Fq;
use ark_bn254::Fr;
pub use ark_ff::AdditiveGroup;
use ark_ff::{BigInteger, PrimeField};
use ruint::aliases::U256;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

/// The base field used for point coordinates in the World ID Protocol.
///
/// This is the field of the BN254 curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BaseField(pub Fq);

impl BaseField {
    /// The zero element of the base field.
    pub const ZERO: Self = Self(Fq::ZERO);
}

/// The scalar field used for multipliers for EC operations in the World ID Protocol.
///
/// This is the field of the BN254 curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarField(pub Fr);

impl Serialize for BaseField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.0.into_bigint();

        if serializer.is_human_readable() {
            let uint = U256::from_limbs(value.0);
            serializer.serialize_str(&format!("{uint:#066x}"))
        } else {
            value.to_bytes_be().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for BaseField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = if deserializer.is_human_readable() {
            let mut s: String = Deserialize::deserialize(deserializer)?;
            if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                s = rest.to_string();
            }

            hex::decode(&s).map_err(D::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };
        // TODO: Check the expected length?
        Ok(Self(Fq::from_be_bytes_mod_order(&bytes)))
    }
}

impl From<u64> for BaseField {
    fn from(value: u64) -> Self {
        Self(Fq::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_base_field_from_u64() {
        let field = BaseField::from(42u64);
        let expected = Fq::from(42u64);
        assert_eq!(field.0, expected);
    }

    #[test]
    fn test_base_field_serialize_human_readable() {
        let field = BaseField::from(255u64);
        let json = serde_json::to_string(&field).unwrap();
        assert_eq!(
            json,
            "\"0x00000000000000000000000000000000000000000000000000000000000000ff\""
        );
    }

    #[test]
    fn test_base_field_serialize_non_human_readable() {
        let field = BaseField::from(255u64);
        let mut bytes = Vec::new();
        ciborium::into_writer(&field, &mut bytes).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_base_field_deserialize_human_readable_with_0x_prefix() {
        let hex_str = "\"0x00000000000000000000000000000000000000000000000000000000000000ff\"";
        let field: BaseField = serde_json::from_str(hex_str).unwrap();
        let expected = BaseField::from(255u64);
        assert_eq!(field, expected);
    }

    #[test]
    fn test_base_field_deserialize_human_readable_without_prefix() {
        let hex_str = "\"00000000000000000000000000000000000000000000000000000000000000ff\"";
        let field: BaseField = serde_json::from_str(hex_str).unwrap();
        let expected = BaseField::from(255u64);
        assert_eq!(field, expected);
    }

    #[test]
    fn test_base_field_round_trip_human_readable() {
        let original = BaseField::from(12345u64);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: BaseField = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_base_field_round_trip_binary() {
        let original = BaseField::from(54321u64);
        let mut bytes = Vec::new();
        ciborium::into_writer(&original, &mut bytes).unwrap();
        let deserialized: BaseField = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_base_field_deserialize_invalid_hex() {
        let invalid_hex = "\"0xGGGG\"";
        let result: Result<BaseField, _> = serde_json::from_str(invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_base_field_zero_serialization() {
        let zero = BaseField::ZERO;

        // Test JSON serialization
        let json = serde_json::to_string(&zero).unwrap();
        let deserialized: BaseField = serde_json::from_str(&json).unwrap();
        assert_eq!(zero, deserialized);

        // Test binary serialization
        let mut bytes = Vec::new();
        ciborium::into_writer(&zero, &mut bytes).unwrap();
        let deserialized: BaseField = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(zero, deserialized);
    }
}
