use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
use std::{fmt, str::FromStr};

use crate::PrimitiveError;

/// An opaque 64-byte signature, stored and serialized identically to
/// `EdDSASignature` in `world-id-primitives` (bare hex for JSON, raw bytes
/// for CBOR). `Option<SignatureBytes>` serializes `None` as null.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignatureBytes([u8; 64]);

impl SignatureBytes {
    /// Returns the raw 64 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Constructs from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl FromStr for SignatureBytes {
    type Err = PrimitiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|e| PrimitiveError::Deserialization(format!("Invalid hex encoding: {e}")))?;
        let arr: [u8; 64] = bytes.try_into().map_err(|_| {
            PrimitiveError::Deserialization("Invalid signature. Expected 64 bytes.".to_string())
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Serializes `Option<SignatureBytes>` as bare hex (JSON) or raw bytes (CBOR),
/// with `None` as null — matching `world-id-primitives`.
pub fn serialize_optional_signature<S>(
    sig: &Option<SignatureBytes>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let Some(sig) = sig else {
        return serializer.serialize_none();
    };
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(sig.0))
    } else {
        serializer.serialize_bytes(&sig.0)
    }
}

/// Deserializes `Option<SignatureBytes>` from bare hex (JSON) or raw bytes (CBOR).
pub fn deserialize_optional_signature<'de, D>(
    deserializer: D,
) -> Result<Option<SignatureBytes>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Option<Vec<u8>> = if deserializer.is_human_readable() {
        Option::<String>::deserialize(deserializer)?
            .map(|s| hex::decode(s).map_err(D::Error::custom))
            .transpose()?
    } else {
        Option::<Vec<u8>>::deserialize(deserializer)?
    };

    let Some(bytes) = bytes else {
        return Ok(None);
    };

    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| D::Error::custom("Invalid signature. Expected 64 bytes."))?;
    Ok(Some(SignatureBytes(arr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let sig = SignatureBytes::from_bytes([0xCD; 64]);
        let s = sig.to_string();
        let back = SignatureBytes::from_str(&s).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn json_roundtrip_via_credential() {
        // Tested through credential tests since serde for Option<SignatureBytes>
        // is only used via the custom serializer on Credential.
    }
}
