use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{fmt, str::FromStr};

use crate::PrimitiveError;

/// An opaque 32-byte public key, stored and serialized identically to
/// `EdDSAPublicKey` in `world-id-primitives` (bare hex for JSON, raw bytes
/// for CBOR).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    /// Returns the raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constructs from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl FromStr for PublicKeyBytes {
    type Err = PrimitiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|e| PrimitiveError::Deserialization(format!("Invalid hex encoding: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            PrimitiveError::Deserialization("Invalid public key. Expected 32 bytes.".to_string())
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes =
                hex::decode(&s).map_err(|e| D::Error::custom(format!("invalid hex: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("Invalid public key. Expected 32 bytes."))?;
            Ok(Self(arr))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("Invalid public key. Expected 32 bytes."))?;
            Ok(Self(arr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let pk = PublicKeyBytes::from_bytes([0xAB; 32]);
        let s = pk.to_string();
        let back = PublicKeyBytes::from_str(&s).unwrap();
        assert_eq!(pk, back);
    }

    #[test]
    fn json_roundtrip() {
        let pk = PublicKeyBytes::from_bytes([0x42; 32]);
        let json = serde_json::to_string(&pk).unwrap();
        let back: PublicKeyBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, back);
    }

    #[test]
    fn cbor_roundtrip() {
        let pk = PublicKeyBytes::from_bytes([0x42; 32]);
        let mut buf = Vec::new();
        ciborium::into_writer(&pk, &mut buf).unwrap();
        let back: PublicKeyBytes = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(pk, back);
    }
}
