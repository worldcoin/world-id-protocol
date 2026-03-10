use std::{fmt::Display, ops::Deref, str::FromStr};

use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{FieldElement, PrimitiveError};

/// A nullifier is a unique, one-time identifier derived from (user, rpId, action) that lets RPs detect
/// duplicate actions without learning who the user is. Used with the contract's `verify()` function.
///
/// Internally, this is a thin wrapper to identify explicitly a single _nullifier_. This wrapper is
/// used to expose explicit canonical serialization which is critical for uniqueness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier {
    /// The `FieldElement` representing the nullifier.
    pub inner: FieldElement,
}

impl Nullifier {
    const PREFIX: &str = "nil_";
    const ENCODING_LENGTH: usize = 64;

    /// Initializes a new [`Nullifier`] from a [`FieldElement`]
    pub const fn new(nullifier: FieldElement) -> Self {
        Self { inner: nullifier }
    }

    /// Outputs the nullifier as a number. This is the **recommended way of enforcing nullifier uniqueness**.
    ///
    /// Store this number directly to enforce uniqueness.
    pub fn as_number(&self) -> U256 {
        self.inner.into()
    }

    /// Serializes a nullifier in a canonical string representation.
    ///
    /// It is generally safe to do uniqueness on nullifiers treating them as strings if you always serialize
    /// them with this method. However, storing nullifiers as numbers instead is recommended.
    ///
    /// # Warning
    /// Using a canonical representation is particularly important for nullifiers. Otherwise, different strings
    /// may actually represent the same field elements, which could result in a compromise of uniqueness.
    ///
    /// # Details
    /// In particular, this method adds an explicit prefix, serializes the field element to a 32-byte hex padded
    /// string with only lowercase characters.
    pub fn to_canonical_string(&self) -> String {
        let value = self
            .inner
            .to_string()
            .trim_start_matches("0x")
            .to_lowercase();
        // len is safe because for all the hex charset, each uses 1 byte
        format!(
            "{}{}{value}",
            Self::PREFIX,
            "0".repeat(Self::ENCODING_LENGTH - value.len())
        )
    }

    /// Deserializes a nullifier from a canonical string representation. In particular,
    /// this method will enforce all the required rules to ensure the value was canonically serialized.
    ///
    /// For example, the following string representations are equivalently the same field element: `0xa`, `0xA`, `0x0A`,
    /// this method will ensure a single representation exists for each field element.
    ///
    /// # Errors
    /// Will return an error if any of the encoding conditions failed (e.g. invalid characters, invalid length, etc.)
    pub fn from_canonical_string(nullifier: String) -> Result<Self, PrimitiveError> {
        let nullifier = nullifier.strip_prefix(Self::PREFIX).ok_or_else(|| {
            PrimitiveError::Deserialization(format!(
                "nullifier must start with the {}",
                Self::PREFIX
            ))
        })?;

        if nullifier
            .chars()
            .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
        {
            return Err(PrimitiveError::Deserialization(
                "nullifier has invalid characters. only lowercase hex characters allowed."
                    .to_string(),
            ));
        }

        if nullifier.len() != Self::ENCODING_LENGTH {
            return Err(PrimitiveError::Deserialization(format!(
                "nullifier does not have the right length. length: {}",
                nullifier.len()
            )));
        }

        let nullifier = FieldElement::from_str(nullifier)?;

        Ok(Self { inner: nullifier })
    }
}

impl Serialize for Nullifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_canonical_string())
        } else {
            // `to_be_bytes()` is guaranteed to return 32 bytes
            serializer.serialize_bytes(&self.inner.to_be_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Nullifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            Self::from_canonical_string(value).map_err(|e| D::Error::custom(e.to_string()))
        } else {
            let bytes = Vec::deserialize(deserializer)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected 32 bytes"))?;
            let nullifier = FieldElement::from_be_bytes(&bytes)
                .map_err(|_| D::Error::custom("invalid field element"))?;
            Ok(Self { inner: nullifier })
        }
    }
}

impl Display for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_canonical_string().fmt(f)
    }
}

impl From<Nullifier> for FieldElement {
    fn from(value: Nullifier) -> Self {
        value.inner
    }
}

impl From<FieldElement> for Nullifier {
    fn from(value: FieldElement) -> Self {
        Self { inner: value }
    }
}

impl From<Nullifier> for U256 {
    fn from(value: Nullifier) -> Self {
        value.as_number()
    }
}

impl Deref for Nullifier {
    type Target = FieldElement;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::uint;

    fn nil(value: u64) -> Nullifier {
        Nullifier::new(FieldElement::from(value))
    }

    #[test]
    fn canonical_string_roundtrip() {
        let nullifier = nil(42);
        let canonical = nullifier.to_canonical_string();
        let recovered = Nullifier::from_canonical_string(canonical.clone()).unwrap();
        assert_eq!(nullifier, recovered);

        let to_string_representation = nullifier.to_string();
        assert_eq!(to_string_representation, canonical);
    }

    #[test]
    fn canonical_string_roundtrip_zero() {
        let nullifier = nil(0);
        let canonical = nullifier.to_canonical_string();
        assert_eq!(
            canonical,
            "nil_0000000000000000000000000000000000000000000000000000000000000000"
        );
        let recovered = Nullifier::from_canonical_string(canonical).unwrap();
        assert_eq!(nullifier, recovered);
    }

    #[test]
    fn canonical_string_roundtrip_large_value() {
        let fe = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();
        let nullifier = Nullifier::new(fe);
        let canonical = nullifier.to_canonical_string();
        assert_eq!(
            canonical,
            "nil_11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2"
        );
        let recovered = Nullifier::from_canonical_string(canonical).unwrap();
        assert_eq!(nullifier, recovered);
    }

    #[test]
    fn canonical_string_is_lowercase_and_zero_padded() {
        let canonical = nil(0xff).to_canonical_string();
        let hex_part = canonical.strip_prefix("nil_").unwrap();
        assert!(
            hex_part
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
        );
        assert_eq!(hex_part.len(), 64);
        assert!(
            hex_part.starts_with("000000000000000000000000000000000000000000000000000000000000")
        );
        assert!(hex_part.ends_with("ff"));
    }

    #[test]
    fn rejects_missing_prefix() {
        let s = "0000000000000000000000000000000000000000000000000000000000000001";
        let err = Nullifier::from_canonical_string(s.to_string()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Deserialization error: nullifier must start with the nil_".to_string()
        );
    }

    #[test]
    fn rejects_wrong_prefix() {
        let s = "nul_0000000000000000000000000000000000000000000000000000000000000001";
        let err = Nullifier::from_canonical_string(s.to_string()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Deserialization error: nullifier must start with the nil_".to_string()
        );
    }

    #[test]
    fn rejects_uppercase_hex() {
        let s = "nil_000000000000000000000000000000000000000000000000000000000000000A";
        let err = Nullifier::from_canonical_string(s.to_string()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Deserialization error: nullifier has invalid characters. only lowercase hex characters allowed.".to_string()
        );
    }

    #[test]
    fn rejects_mixed_case() {
        let s = "nil_000000000000000000000000000000000000000000000000000000000000aAbB";
        let err = Nullifier::from_canonical_string(s.to_string()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Deserialization error: nullifier has invalid characters. only lowercase hex characters allowed.".to_string()
        );
    }

    #[test]
    fn rejects_unpadded_short() {
        // Valid field element but not zero-padded to 64 chars
        let s = "nil_a";
        let err = Nullifier::from_canonical_string(s.to_string()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Deserialization error: nullifier does not have the right length. length: 1"
                .to_string()
        );
    }

    #[test]
    fn rejects_too_long() {
        let s = "nil_00000000000000000000000000000000000000000000000000000000000000001";
        assert!(Nullifier::from_canonical_string(s.to_string()).is_err());
    }

    #[test]
    fn rejects_non_hex_characters() {
        let s = "nil_000000000000000000000000000000000000000000000000000000000000gggg";
        assert!(Nullifier::from_canonical_string(s.to_string()).is_err());
    }

    #[test]
    fn rejects_0x_prefix_inside_canonical() {
        let s = "nil_0x0000000000000000000000000000000000000000000000000000000000000a";
        assert!(Nullifier::from_canonical_string(s.to_string()).is_err());
    }

    #[test]
    fn non_canonical_representations_of_same_value_rejected() {
        // All of these represent field element 10, but only the canonical form is accepted.
        let non_canonical = [
            "nil_000000000000000000000000000000000000000000000000000000000000000A", // uppercase
            "nil_a",                                                                // unpadded
            "nil_0a", // partially padded
            "nil_0A", // uppercase + unpadded
            "nil_00000000000000000000000000000000000000000000000000000000000000a", // 63 chars
            "nil_0000000000000000000000000000000000000000000000000000000000000000a", // 65 chars
        ];

        for s in non_canonical {
            assert!(
                Nullifier::from_canonical_string(s.to_string()).is_err(),
                "should reject non-canonical: {s}"
            );
        }
    }

    #[test]
    fn as_number_returns_inner_u256() {
        let nullifier = nil(12345);
        assert_eq!(nullifier.as_number(), U256::from(12345));
    }

    #[test]
    fn json_roundtrip() {
        let nullifier = nil(42);
        let json = serde_json::to_string(&nullifier).unwrap();
        let recovered: Nullifier = serde_json::from_str(&json).unwrap();
        assert_eq!(nullifier, recovered);
    }

    #[test]
    fn json_uses_canonical_format() {
        let nullifier = nil(255);
        let json = serde_json::to_string(&nullifier).unwrap();
        let expected = format!("\"{}\"", nullifier.to_canonical_string());
        assert_eq!(json, expected);
    }

    #[test]
    fn json_rejects_non_canonical_input() {
        // Valid field element, but uppercase hex
        let json = "\"nil_000000000000000000000000000000000000000000000000000000000000000A\"";
        assert!(serde_json::from_str::<Nullifier>(json).is_err());

        // Valid field element, but no prefix
        let json = "\"0000000000000000000000000000000000000000000000000000000000000001\"";
        assert!(serde_json::from_str::<Nullifier>(json).is_err());
    }

    #[test]
    fn cbor_roundtrip() {
        let nullifier = nil(42);
        let mut buf = Vec::new();
        ciborium::into_writer(&nullifier, &mut buf).unwrap();
        let recovered: Nullifier = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(nullifier, recovered);
    }

    #[test]
    fn json_and_cbor_decode_to_same_value() {
        let nullifier = nil(999);

        let json = serde_json::to_string(&nullifier).unwrap();
        let from_json: Nullifier = serde_json::from_str(&json).unwrap();

        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&nullifier, &mut cbor_buf).unwrap();
        let from_cbor: Nullifier = ciborium::from_reader(&cbor_buf[..]).unwrap();

        assert_eq!(from_json, from_cbor);
    }
}
