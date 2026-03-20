use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{fmt, str::FromStr};

use crate::PrimitiveError;

/// BN254 scalar field modulus (= BabyJubJub base field modulus).
///
/// `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
const MODULUS: U256 =
    ruint::uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

/// A field element stored as 32 big-endian bytes, validated to be less than
/// the BN254 scalar field modulus.
///
/// Serialization matches [`world_id_primitives::FieldElement`]:
/// - Human-readable (JSON): `"0x"` + 64 hex chars
/// - Binary (CBOR): 32-byte blob
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FieldElement([u8; 32]);

impl FieldElement {
    /// The additive identity of the field.
    pub const ZERO: Self = Self([0u8; 32]);

    /// The multiplicative identity of the field.
    pub const ONE: Self = {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        Self(bytes)
    };

    /// Returns the 32-byte big-endian representation.
    #[must_use]
    pub const fn to_be_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Constructs a field element from 32 big-endian bytes.
    ///
    /// # Errors
    /// Returns [`PrimitiveError::NotInField`] if the value >= the field modulus.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Result<Self, PrimitiveError> {
        let value = U256::from_be_bytes(*bytes);
        if value >= MODULUS {
            return Err(PrimitiveError::NotInField);
        }
        Ok(Self(*bytes))
    }

    /// Converts to a `U256`.
    #[must_use]
    pub const fn to_u256(&self) -> U256 {
        U256::from_be_bytes(self.0)
    }
}

impl FromStr for FieldElement {
    type Err = PrimitiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s)
            .map_err(|e| PrimitiveError::Deserialization(format!("Invalid hex encoding: {e}")))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PrimitiveError::Deserialization("expected 32 bytes".to_string()))?;
        Self::from_be_bytes(&bytes)
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<u64> for FieldElement {
    fn from(value: u64) -> Self {
        let u = U256::from(value);
        Self(u.to_be_bytes())
    }
}

impl From<u128> for FieldElement {
    fn from(value: u128) -> Self {
        let u = U256::from(value);
        Self(u.to_be_bytes())
    }
}

impl TryFrom<U256> for FieldElement {
    type Error = PrimitiveError;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value >= MODULUS {
            return Err(PrimitiveError::NotInField);
        }
        Ok(Self(value.to_be_bytes()))
    }
}

impl From<FieldElement> for U256 {
    fn from(value: FieldElement) -> Self {
        Self::from_be_bytes(value.0)
    }
}

impl TryFrom<FieldElement> for u64 {
    type Error = PrimitiveError;

    fn try_from(value: FieldElement) -> Result<Self, Self::Error> {
        let u = U256::from_be_bytes(value.0);
        u.try_into().map_err(|_| PrimitiveError::OutOfBounds)
    }
}

impl TryFrom<FieldElement> for usize {
    type Error = PrimitiveError;

    fn try_from(value: FieldElement) -> Result<Self, Self::Error> {
        let u = U256::from_be_bytes(value.0);
        u.try_into().map_err(|_| PrimitiveError::OutOfBounds)
    }
}

impl Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(D::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected 32 bytes"))?;
            Self::from_be_bytes(&bytes).map_err(D::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::uint;

    #[test]
    fn json_roundtrip() {
        let fe = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();
        let json = serde_json::to_string(&fe).unwrap();
        assert_eq!(
            json,
            "\"0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2\""
        );
        let back: FieldElement = serde_json::from_str(&json).unwrap();
        assert_eq!(fe, back);
    }

    #[test]
    fn cbor_roundtrip() {
        let fe = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();
        let mut buf = Vec::new();
        ciborium::into_writer(&fe, &mut buf).unwrap();
        let back: FieldElement = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(fe, back);
    }

    #[test]
    fn cbor_binary_format() {
        let fe = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();
        let mut buf = Vec::new();
        ciborium::into_writer(&fe, &mut buf).unwrap();
        // CBOR: byte string header (2 bytes) + 32 bytes
        assert_eq!(buf.len(), 34);
        assert_eq!(buf[0], 0x58); // byte string, 1-byte length follows
        assert_eq!(buf[1], 0x20); // 32
    }

    #[test]
    fn rejects_above_modulus() {
        let bytes = [0xFF; 32];
        assert_eq!(
            FieldElement::from_be_bytes(&bytes),
            Err(PrimitiveError::NotInField)
        );
    }

    #[test]
    fn from_conversions() {
        assert_eq!(FieldElement::from(0u64), FieldElement::ZERO);
        assert_eq!(FieldElement::from(1u64), FieldElement::ONE);
        assert_eq!(FieldElement::from(1u128), FieldElement::ONE);
    }

    #[test]
    fn display_from_str_roundtrip() {
        let fe = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();
        let s = fe.to_string();
        assert_eq!(FieldElement::from_str(&s).unwrap(), fe);
    }

    #[test]
    fn from_str_rejects_wrong_length() {
        assert!(FieldElement::from_str("0x01").is_err());
        assert!(FieldElement::from_str(
            "0x000000000000000000000000000000000000000000000000000000000000000001"
        )
        .is_err());
    }

    #[test]
    fn zero_and_one_json() {
        assert_eq!(
            serde_json::to_string(&FieldElement::ZERO).unwrap(),
            "\"0x0000000000000000000000000000000000000000000000000000000000000000\""
        );
        assert_eq!(
            serde_json::to_string(&FieldElement::ONE).unwrap(),
            "\"0x0000000000000000000000000000000000000000000000000000000000000001\""
        );
    }

    #[test]
    fn u256_roundtrip() {
        let original =
            uint!(0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256);
        let fe = FieldElement::try_from(original).unwrap();
        let back: U256 = fe.into();
        assert_eq!(original, back);
    }
}
