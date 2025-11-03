//! This crate contains the raw base types (without implementation) for the World ID Protocol.
//!
//! It implements basic primitives such as field elements, proofs, the format of requests and responses, etc.
//!
//! Importantly, this crate keeps dependencies to a minimum and does not implement any logic beyond serialization and deserialization.
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

use ark_babyjubjub::Fq;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ruint::aliases::U256;
use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt,
    io::{Cursor, Read, Write},
    ops::{Deref, DerefMut},
    str::FromStr,
};

/// Contains types related to the Authenticator.
pub mod authenticator;

/// Contains the global configuration for interacting with the World ID Protocol.
mod config;
pub use config::Config;

/// Base definition of a "Credential" in the World ID Protocol.
pub mod credential;
pub use credential::{Credential, CredentialVersion};

/// Contains base types for operations with Merkle trees.
pub mod merkle;

/// Contains the quintessential proof type.
pub mod proof;
pub use proof::WorldIdProof;

/// Contains types specifically related to relying parties.
pub mod rp;

/// The scalar field used in the World ID Protocol.
///
/// This is the scalar field of the `BabyJubJub` curve.
pub type ScalarField = ark_babyjubjub::Fr;

/// The depth of the Merkle tree used in the World ID Protocol for the `AccountRegistry` contract.
pub const TREE_DEPTH: usize = 30;

/// Represents a field element of the base field (`Fq`) in the World ID Protocol.
///
/// The World ID Protocol uses the `BabyJubJub` curve throughout. Note the
/// base field of `BabyJubJub` is the scalar field of the BN254 curve.
///
/// This wrapper ensures consistent serialization and deserialization of field elements, where
/// string-based serialization is done with hex encoding and binary serialization is done with byte vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FieldElement(Fq);

impl FieldElement {
    /// The additive identity of the field.
    pub const ZERO: Self = Self(Fq::ZERO);
    /// The multiplicative identity of the field.
    pub const ONE: Self = Self(Fq::ONE);

    /// Serializes the field element into a byte vector.
    ///
    /// # Errors
    /// Will return an error if the serialization unexpectedly fails.
    pub fn serialize_as_bytes<W: Write>(&self, writer: &mut W) -> Result<(), PrimitiveError> {
        self.0
            .serialize_compressed(writer)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))
    }

    /// Deserializes a field element from a byte vector.
    ///
    /// # Errors
    /// Will return an error if the provided input is not a valid field element (e.g. not on the curve).
    pub fn deserialize_from_bytes<R: Read>(bytes: &mut R) -> Result<Self, PrimitiveError> {
        let field_element = Fq::deserialize_compressed(bytes)
            .map_err(|e| PrimitiveError::Deserialization(e.to_string()))?;
        Ok(Self(field_element))
    }

    /// Deserializes a field element from a big-endian byte slice.
    #[must_use]
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let field_element = Fq::from_be_bytes_mod_order(bytes);
        Self(field_element)
    }
}

impl Deref for FieldElement {
    type Target = Fq;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FieldElement {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromStr for FieldElement {
    type Err = PrimitiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches("0x");
        let u256 = U256::from_str_radix(s, 16).map_err(|_| {
            PrimitiveError::Deserialization("not a valid hex-encoded number".to_string())
        })?;
        u256.try_into()
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u256: U256 = (*self).into();
        write!(f, "{u256:#066x}")
    }
}

impl From<Fq> for FieldElement {
    fn from(value: Fq) -> Self {
        Self(value)
    }
}

impl TryFrom<U256> for FieldElement {
    type Error = PrimitiveError;
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Ok(Self(
            value.try_into().map_err(|_| PrimitiveError::NotInField)?,
        ))
    }
}

impl From<FieldElement> for U256 {
    fn from(value: FieldElement) -> Self {
        <Self as From<Fq>>::from(value.0)
    }
}

impl From<u64> for FieldElement {
    fn from(value: u64) -> Self {
        Self(Fq::from(value))
    }
}

impl From<u128> for FieldElement {
    fn from(value: u128) -> Self {
        Self(Fq::from(value))
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
            Self::from_str(&s).map_err(D::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::deserialize_from_bytes(&mut Cursor::new(bytes)).map_err(D::Error::custom)
        }
    }
}

/// Generic errors that may occur with basic serialization and deserialization.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PrimitiveError {
    /// Error that occurs when serializing a value. Generally not expected.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Error that occurs when deserializing a value. This can happen often when not providing valid inputs.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    /// Number is equal or larger than the target field modulus.
    #[error("Provided value is not in the field")]
    NotInField,
    /// Index is out of bounds.
    #[error("Provided index is out of bounds")]
    OutOfBounds,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::uint;

    #[test]
    fn test_field_element_encoding() {
        let root = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();

        assert_eq!(
            serde_json::to_string(&root).unwrap(),
            "\"0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2\""
        );

        assert_eq!(
            root.to_string(),
            "0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2"
        );

        let fe = FieldElement::ONE;
        assert_eq!(
            serde_json::to_string(&fe).unwrap(),
            "\"0x0000000000000000000000000000000000000000000000000000000000000001\""
        );

        let md = FieldElement::ZERO;
        assert_eq!(
            serde_json::to_string(&md).unwrap(),
            "\"0x0000000000000000000000000000000000000000000000000000000000000000\""
        );

        assert_eq!(*FieldElement::ONE, Fq::ONE);
    }

    #[test]
    fn test_field_element_decoding() {
        let root = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();

        assert_eq!(
            serde_json::from_str::<FieldElement>(
                "\"0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2\""
            )
            .unwrap(),
            root
        );

        assert_eq!(
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            )
            .unwrap(),
            FieldElement::ONE
        );
    }

    #[test]
    fn test_field_element_binary_encoding_roundtrip() {
        let root = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();

        let mut buffer = Vec::new();
        ciborium::into_writer(&root, &mut buffer).unwrap();

        let decoded: FieldElement = ciborium::from_reader(&buffer[..]).unwrap();

        assert_eq!(root, decoded);
    }

    #[test]
    fn test_field_element_binary_encoding_format() {
        let root = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();

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
