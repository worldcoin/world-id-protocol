//! This crate contains the raw base types (without implementation) for the World ID Protocol.
//!
//! It implements basic primitives such as field elements, proofs, the format of requests and responses, etc.
//!
//! Importantly, this crates keeps dependencies to a minimum and does not implement any logic beyond serialization and deserialization.
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

use std::{
    fmt,
    io::{Cursor, Read, Write},
    str::FromStr,
};

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ruint::aliases::U256;
use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// Module containing the quintessential proof type.
pub mod proof;
pub use proof::WorldIdProof;

/// Module containing types related specific to relying parties.
pub mod rp;

/// The base field (curve field `Fq`) over which the elliptic curve is
/// defined for the curve that is used to sign credentials in the World ID Protocol.
///
/// The World ID Protocol currently uses the `BabyJubJub` curve.
pub type BaseField = ark_babyjubjub::Fq;

/// Represents a Merkle root hash for any of the trees in the World ID Protocol.
///
/// The inner type is a base field element from `BabyJubJub` for convenience instead of a scalar field element on BN254.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FieldElement(BaseField);

impl FieldElement {
    /// Serializes the field element into a compressed byte vector.
    ///
    /// # Errors
    /// Will return an error if the serialization unexpectedly fails.
    pub fn serialize_compressed<W: Write>(&self, writer: &mut W) -> Result<(), TypeError> {
        self.0
            .serialize_compressed(writer)
            .map_err(|e| TypeError::Serialization(e.to_string()))
    }

    /// Deserializes a field element from a compressed byte vector.
    ///
    /// # Errors
    /// Will return an error if the provided input is not a valid compressed field element (e.g. not on the curve).
    pub fn deserialize_compressed<R: Read>(bytes: &mut R) -> Result<Self, TypeError> {
        let field_element = BaseField::deserialize_compressed(bytes)
            .map_err(|e| TypeError::Deserialization(e.to_string()))?;
        Ok(Self(field_element))
    }
}

impl FromStr for FieldElement {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(ark_babyjubjub::Fq::from_str(s)?))
    }
}

impl From<U256> for FieldElement {
    fn from(value: U256) -> Self {
        Self(BaseField::new(ark_ff::BigInt(value.into_limbs())))
    }
}

impl From<FieldElement> for U256 {
    fn from(value: FieldElement) -> Self {
        Self::from_limbs(value.0.into_bigint().0)
    }
}

impl From<BaseField> for FieldElement {
    fn from(value: BaseField) -> Self {
        Self(value)
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u256: U256 = (*self).into();
        write!(f, "{u256:#066x}")
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
            let mut writer = Vec::new();
            self.serialize_compressed(&mut writer)
                .map_err(S::Error::custom)?;
            serializer.serialize_bytes(&writer)
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
            let s = s.trim_start_matches("0x");
            let u256 = U256::from_str_radix(s, 16).map_err(D::Error::custom)?;
            Ok(Self::from(u256))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::deserialize_compressed(&mut Cursor::new(bytes)).map_err(D::Error::custom)
        }
    }
}

/// Generic errors that may occur with basic serialization and deserialization.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TypeError {
    /// Error that occurs when serializing a value. Generally not expected.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Error that occurs when deserializing a value. This can happen often when not providing valid inputs.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, Field};
    use ruint::uint;

    #[test]
    fn test_field_element_encoding() {
        let root = FieldElement::from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ));

        assert_eq!(
            serde_json::to_string(&root).unwrap(),
            "\"0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2\""
        );

        assert_eq!(
            root.0,
            BaseField::try_from(uint!(
                0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
            ))
            .unwrap()
        );

        let fe = FieldElement::from(BaseField::ONE);
        assert_eq!(
            serde_json::to_string(&fe).unwrap(),
            "\"0x0000000000000000000000000000000000000000000000000000000000000001\""
        );

        let md = FieldElement::from(BaseField::ZERO);
        assert_eq!(
            serde_json::to_string(&md).unwrap(),
            "\"0x0000000000000000000000000000000000000000000000000000000000000000\""
        );
    }

    #[test]
    fn test_field_element_decoding() {
        let root = FieldElement::from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ));

        assert_eq!(
            serde_json::from_str::<FieldElement>(
                "\"0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2\""
            )
            .unwrap(),
            root
        );
    }

    #[test]
    fn test_field_element_binary_encoding_roundtrip() {
        let root = FieldElement::from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ));

        let mut buffer = Vec::new();
        ciborium::into_writer(&root, &mut buffer).unwrap();

        let decoded: FieldElement = ciborium::from_reader(&buffer[..]).unwrap();

        assert_eq!(root, decoded);
    }

    #[test]
    fn test_field_element_binary_encoding_format() {
        let root = FieldElement::from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ));

        // Serialize to CBOR (binary format)
        let mut buffer = Vec::new();
        ciborium::into_writer(&root, &mut buffer).unwrap();

        assert_eq!(buffer.len(), 34); // CBOR header (2 bytes) + field element (32 bytes)
        assert_eq!(buffer[0], 0x58); // CBOR byte string, 1-byte length follows
        assert_eq!(buffer[1], 0x20); // Length = 32 bytes

        let field_bytes = &buffer[2..];
        assert_eq!(field_bytes.len(), 32);

        let expected_le_bytes =
            hex::decode("c224d31e05d194f1b7ac32eaa4dbfce39a43a3f050cf422f21ac917bce23d211")
                .unwrap();
        assert_eq!(field_bytes, expected_le_bytes.as_slice());
    }
}
