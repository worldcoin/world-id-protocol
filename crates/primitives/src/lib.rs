//! This crate contains the raw base types (without implementation) for the World ID Protocol.
//!
//! It implements basic primitives such as field elements, proofs, the format of requests and responses, etc.
//!
//! Importantly, this crate keeps dependencies to a minimum and does not implement any logic beyond serialization and deserialization.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![deny(clippy::all, clippy::nursery, missing_docs, dead_code)]
#![allow(clippy::option_if_let_else)]

use alloy_primitives::Keccak256;

use ark_babyjubjub::Fq;
use ark_ff::{AdditiveGroup, Field, PrimeField, UniformRand};
use ruint::aliases::{U160, U256};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{
    fmt,
    ops::{Deref, DerefMut},
    str::FromStr,
};

/// Contains types related to the Authenticator.
pub mod authenticator;

/// Contains the global configuration for interacting with the World ID Protocol.
mod config;
pub use config::Config;

/// Contains the raw circuit input types for the World ID Protocol.
///
/// These types are used to prepare the inputs for the Groth16 circuits.
pub mod circuit_inputs;

/// SAFE-style sponge utilities and helpers.
pub mod sponge;

/// Base definition of a "Credential" in the World ID Protocol.
pub mod credential;
pub use credential::{Credential, CredentialVersion};

/// Contains base types for operations with Merkle trees.
pub mod merkle;

/// Contains API request/response types and shared API enums.
pub mod api_types;

/// Contains types specifically related to the OPRF services.
pub mod oprf;

/// Contains the session nullifier type for session proof responses.
pub mod nullifier;
pub use nullifier::SessionNullifier;

/// Contains the quintessential zero-knowledge proof type.
pub mod proof;
pub use proof::ZeroKnowledgeProof;

/// Contains types specifically related to relying parties.
pub mod rp;

pub mod serde_utils;

/// Contains signer primitives for on-chain and off-chain signatures.
mod signer;
pub use signer::Signer;

/// Contains request/response types and validation helpers for RP proof requests.
pub mod request;
pub use request::{
    ConstraintExpr, ConstraintKind, ConstraintNode, MAX_CONSTRAINT_NODES, ProofRequest,
    ProofResponse, RequestItem, RequestVersion, ResponseItem, ValidationError,
};

/// The scalar field used in the World ID Protocol.
///
/// This is the scalar field of the `BabyJubJub` curve.
pub type ScalarField = ark_babyjubjub::Fr;

/// The depth of the Merkle tree used in the World ID Protocol for the `WorldIDRegistry` contract.
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

    /// Returns the 32-byte big-endian representation of this field element.
    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let num: U256 = self.0.into_bigint().into();
        num.to_be_bytes()
    }

    /// Constructs a field element from a 32-byte big-endian representation.
    ///
    /// Unlike `from_be_bytes_mod_order`, this rejects values >= the field modulus.
    ///
    /// # Errors
    /// Returns [`PrimitiveError::NotInField`] if the value is >= the field modulus.
    pub fn from_be_bytes(be_bytes: &[u8; 32]) -> Result<Self, PrimitiveError> {
        U256::from_be_bytes(*be_bytes).try_into()
    }

    /// Deserializes a field element from a big-endian byte slice.
    ///
    /// # Warning
    /// Use this function carefully. This function will perform modulo reduction on the input, which may lead to unexpected results if the input should not be reduced.
    #[must_use]
    pub(crate) fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let field_element = Fq::from_be_bytes_mod_order(bytes);
        Self(field_element)
    }

    /// Takes arbitrary raw bytes, hashes them with a byte-friendly gas-efficient hash function
    /// and reduces it to a field element.
    #[must_use]
    pub fn from_arbitrary_raw_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(bytes);
        let output: [u8; 32] = hasher.finalize().into();

        let n = U256::from_be_bytes(output);
        // Shift right one byte to make it fit in the field
        let n: U256 = n >> 8;

        let field_element = Fq::from_bigint(n.into());

        match field_element {
            Some(element) => Self(element),
            None => unreachable!(
                "due to the byte reduction, the value is guaranteed to be within the field"
            ),
        }

        // FIXME: add unit tests
    }

    /// Generates a random field element using the system's CSPRNG.
    #[must_use]
    pub fn random<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let field_element = Fq::rand(rng);
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

    /// Parses a field element from a hex string (with optional "0x" prefix).
    ///
    /// The value must be lower than the modulus and specifically for string encoding, proper padding is enforced (strictly 32 bytes). This
    /// is because some values in the Protocol are meant to be enforced uniqueness with, and this reduces the possibility of accidental
    /// string non-collisions.
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
        write!(f, "0x{}", hex::encode(self.to_be_bytes()))
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

// safe because U160 is guaranteed to be less than the field modulus.
impl From<U160> for FieldElement {
    fn from(value: U160) -> Self {
        // convert U160 to U256 to reuse existing implementations
        let u256 = U256::from(value);
        let big_int = ark_ff::BigInt(u256.into_limbs());
        Self(ark_babyjubjub::Fq::new(big_int))
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
            serializer.serialize_bytes(&self.to_be_bytes())
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
    /// Invalid input provided (e.g., incorrect length, format, etc.)
    #[error("Invalid input at {attribute}: {reason}")]
    InvalidInput {
        /// The attribute that is invalid
        attribute: String,
        /// The reason the input is invalid
        reason: String,
    },
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
    fn test_simple_bytes_encoding() {
        let fe = FieldElement::ONE;
        let bytes = fe.to_be_bytes();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(bytes, expected);

        let reversed = FieldElement::from_be_bytes(&bytes).unwrap();
        assert_eq!(reversed, fe);
    }

    #[test]
    fn test_field_element_cbor_encoding_roundtrip() {
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

        let expected_be_bytes =
            hex::decode("11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2")
                .unwrap();
        assert_eq!(field_bytes, expected_be_bytes.as_slice());
    }

    #[test]
    fn test_to_be_bytes_from_be_bytes_roundtrip() {
        let values = [
            FieldElement::ZERO,
            FieldElement::ONE,
            FieldElement::from(255u64),
            FieldElement::from(u64::MAX),
            FieldElement::from(u128::MAX),
            FieldElement::try_from(uint!(
                0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
            ))
            .unwrap(),
        ];
        for fe in values {
            let bytes = fe.to_be_bytes();
            let recovered = FieldElement::from_be_bytes(&bytes).unwrap();
            assert_eq!(fe, recovered);
        }
    }

    #[test]
    fn test_from_be_bytes_rejects_value_above_modulus() {
        // The BN254 field is 254 bits
        let bytes = [0xFF; 32];
        assert_eq!(
            FieldElement::from_be_bytes(&bytes),
            Err(PrimitiveError::NotInField)
        );
    }

    #[test]
    fn test_from_str_rejects_wrong_length() {
        // Too short (< 64 hex chars)
        assert!(FieldElement::from_str("0x01").is_err());
        // Too long (> 64 hex chars)
        assert!(
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000000001"
            )
            .is_err()
        );
        // Not hex
        assert!(
            FieldElement::from_str(
                "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
            )
            .is_err()
        );
    }

    #[test]
    fn test_display_from_str_roundtrip() {
        let fe = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();
        let s = fe.to_string();
        assert_eq!(FieldElement::from_str(&s).unwrap(), fe);
    }

    #[test]
    fn test_json_cbor_consistency() {
        // The same value serialized through JSON and CBOR should
        // produce the same FieldElement when deserialized back.
        let fe = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();

        let json_str = serde_json::to_string(&fe).unwrap();
        let from_json: FieldElement = serde_json::from_str(&json_str).unwrap();

        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&fe, &mut cbor_buf).unwrap();
        let from_cbor: FieldElement = ciborium::from_reader(&cbor_buf[..]).unwrap();

        assert_eq!(from_json, from_cbor);
    }

    #[test]
    fn test_to_be_bytes_is_big_endian() {
        let fe = FieldElement::from(1u64);
        let bytes = fe.to_be_bytes();
        assert_eq!(bytes[31], 1); // 1 is in LSB
        assert_eq!(bytes[..31], [0u8; 31]);

        let fe256 = FieldElement::from(256u64);
        let bytes = fe256.to_be_bytes();
        assert_eq!(bytes[30], 1);
        assert_eq!(bytes[31], 0);
    }

    #[test]
    fn test_u256_roundtrip() {
        let original =
            uint!(0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256);
        let fe = FieldElement::try_from(original).unwrap();
        let back: U256 = fe.into();
        assert_eq!(original, back);
    }
}
