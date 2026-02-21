use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::FieldElement;

/// A session nullifier for World ID Session proofs.
///
/// They are an adaptation that reuses the same proof system inputs for session flows:
/// - the nullifier component lets RPs detect replayed submissions for the same proof context
/// - the action component is randomized for session verification semantics
///
/// Together they include:
/// - the nullifier used as the proof output
/// - a random action bound to the same proof
///
/// The `WorldIDVerifier.sol` contract expects this as a `uint256[2]` array
/// use `as_ethereum_representation()` for conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionNullifier {
    /// The nullifier value for this proof.
    nullifier: FieldElement,
    /// The random action value bound to this session proof.
    action: FieldElement,
}

impl SessionNullifier {
    const JSON_PREFIX: &str = "snil_";

    /// Creates a new session nullifier.
    #[must_use]
    pub const fn new(nullifier: FieldElement, action: FieldElement) -> Self {
        Self { nullifier, action }
    }

    /// Returns the nullifier value.
    #[must_use]
    pub const fn nullifier(&self) -> FieldElement {
        self.nullifier
    }

    /// Returns the action value.
    #[must_use]
    pub const fn action(&self) -> FieldElement {
        self.action
    }

    /// Returns the session nullifier as an Ethereum-compatible array for `verifySession()`.
    ///
    /// Format: `[nullifier, action]` matching the contract's `uint256[2] sessionNullifier`.
    #[must_use]
    pub fn as_ethereum_representation(&self) -> [U256; 2] {
        [self.nullifier.into(), self.action.into()]
    }

    /// Creates a session nullifier from an Ethereum representation.
    ///
    /// # Errors
    /// Returns an error if the U256 values are not valid field elements.
    pub fn from_ethereum_representation(value: [U256; 2]) -> Result<Self, String> {
        let nullifier =
            FieldElement::try_from(value[0]).map_err(|e| format!("invalid nullifier: {e}"))?;
        let action =
            FieldElement::try_from(value[1]).map_err(|e| format!("invalid action: {e}"))?;
        Ok(Self { nullifier, action })
    }

    /// Returns the 64-byte big-endian representation (2 x 32-byte field elements).
    #[must_use]
    pub fn to_compressed_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.nullifier.to_be_bytes());
        bytes[32..].copy_from_slice(&self.action.to_be_bytes());
        bytes
    }

    /// Constructs from compressed bytes (must be exactly 64 bytes).
    ///
    /// # Errors
    /// Returns an error if the input is not exactly 64 bytes or if values are not valid field elements.
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 64 {
            return Err(format!(
                "Invalid length: expected 64 bytes, got {}",
                bytes.len()
            ));
        }

        let nullifier = FieldElement::from_be_bytes(bytes[..32].try_into().unwrap())
            .map_err(|e| format!("invalid nullifier: {e}"))?;
        let action = FieldElement::from_be_bytes(bytes[32..].try_into().unwrap())
            .map_err(|e| format!("invalid action: {e}"))?;

        Ok(Self { nullifier, action })
    }
}

impl Default for SessionNullifier {
    fn default() -> Self {
        Self {
            nullifier: FieldElement::ZERO,
            action: FieldElement::ZERO,
        }
    }
}

impl Serialize for SessionNullifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_compressed_bytes();
        if serializer.is_human_readable() {
            // JSON: prefixed hex-encoded compressed bytes for explicit typing.
            serializer.serialize_str(&format!("{}{}", Self::JSON_PREFIX, hex::encode(bytes)))
        } else {
            // Binary: compressed bytes
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for SessionNullifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let hex_str = value.strip_prefix(Self::JSON_PREFIX).ok_or_else(|| {
                D::Error::custom(format!(
                    "session nullifier must start with '{}'",
                    Self::JSON_PREFIX
                ))
            })?;
            hex::decode(hex_str).map_err(D::Error::custom)?
        } else {
            Vec::deserialize(deserializer)?
        };

        Self::from_compressed_bytes(&bytes).map_err(D::Error::custom)
    }
}

impl From<SessionNullifier> for [U256; 2] {
    fn from(value: SessionNullifier) -> Self {
        value.as_ethereum_representation()
    }
}

impl From<(FieldElement, FieldElement)> for SessionNullifier {
    fn from((nullifier, action): (FieldElement, FieldElement)) -> Self {
        Self::new(nullifier, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_field_element(value: u64) -> FieldElement {
        FieldElement::from(value)
    }

    #[test]
    fn test_new_and_accessors() {
        let nullifier = test_field_element(1001);
        let action = test_field_element(42);
        let session = SessionNullifier::new(nullifier, action);

        assert_eq!(session.nullifier(), nullifier);
        assert_eq!(session.action(), action);
    }

    #[test]
    fn test_as_ethereum_representation() {
        let nullifier = test_field_element(100);
        let action = test_field_element(200);
        let session = SessionNullifier::new(nullifier, action);

        let repr = session.as_ethereum_representation();
        assert_eq!(repr[0], U256::from(100));
        assert_eq!(repr[1], U256::from(200));
    }

    #[test]
    fn test_from_ethereum_representation() {
        let repr = [U256::from(100), U256::from(200)];
        let session = SessionNullifier::from_ethereum_representation(repr).unwrap();

        assert_eq!(session.nullifier(), test_field_element(100));
        assert_eq!(session.action(), test_field_element(200));
    }

    #[test]
    fn test_json_roundtrip() {
        let session = SessionNullifier::new(test_field_element(1001), test_field_element(42));
        let json = serde_json::to_string(&session).unwrap();

        // Verify JSON uses the prefixed compact representation
        assert!(json.starts_with("\"snil_"));
        assert!(json.ends_with('"'));

        // Verify roundtrip
        let decoded: SessionNullifier = serde_json::from_str(&json).unwrap();
        assert_eq!(session, decoded);
    }

    #[test]
    fn test_json_format() {
        let session = SessionNullifier::new(test_field_element(1), test_field_element(2));
        let json = serde_json::to_string(&session).unwrap();

        // Should be a prefixed compact string
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_string());
        let value = parsed.as_str().unwrap();
        assert!(value.starts_with("snil_"));
    }

    #[test]
    fn test_bytes_roundtrip() {
        let session = SessionNullifier::new(test_field_element(1001), test_field_element(42));
        let bytes = session.to_compressed_bytes();

        assert_eq!(bytes.len(), 64); // 32 + 32 bytes

        let decoded = SessionNullifier::from_compressed_bytes(&bytes).unwrap();
        assert_eq!(session, decoded);
    }

    #[test]
    fn test_bytes_use_field_element_encoding() {
        let session = SessionNullifier::new(test_field_element(1001), test_field_element(42));
        let bytes = session.to_compressed_bytes();

        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&session.nullifier().to_be_bytes());
        expected[32..].copy_from_slice(&session.action().to_be_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_invalid_bytes_length() {
        let too_short = vec![0u8; 63];
        let result = SessionNullifier::from_compressed_bytes(&too_short);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid length"));

        let too_long = vec![0u8; 65];
        let result = SessionNullifier::from_compressed_bytes(&too_long);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid length"));
    }

    #[test]
    fn test_default() {
        let session = SessionNullifier::default();
        assert_eq!(session.nullifier(), FieldElement::ZERO);
        assert_eq!(session.action(), FieldElement::ZERO);
    }

    #[test]
    fn test_from_tuple() {
        let nullifier = test_field_element(100);
        let action = test_field_element(200);
        let session: SessionNullifier = (nullifier, action).into();

        assert_eq!(session.nullifier(), nullifier);
        assert_eq!(session.action(), action);
    }

    #[test]
    fn test_into_u256_array() {
        let session = SessionNullifier::new(test_field_element(100), test_field_element(200));
        let arr: [U256; 2] = session.into();

        assert_eq!(arr[0], U256::from(100));
        assert_eq!(arr[1], U256::from(200));
    }
}
