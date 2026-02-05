//! Session nullifier type for World ID Session proofs.
//!
//! For Uniqueness proofs, the nullifier is a simple `FieldElement` (or `Option<FieldElement>`
//! in response types). For Session proofs, this module provides [`SessionNullifier`] which
//! packs both the nullifier and action values together.

use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::FieldElement;

/// A session nullifier for World ID Session proofs.
///
/// Session proofs produce both a nullifier and an action value that are cryptographically
/// bound together. The contract's `verifySession()` function expects these as a
/// `uint256[2] calldata sessionNullifier` array where:
/// - `sessionNullifier[0]` is the nullifier
/// - `sessionNullifier[1]` is the action
///
/// # Serialization
///
/// **JSON (human-readable):** A 2-element array matching the contract's `uint256[2]` layout:
/// ```json
/// ["0x1234...abcd", "0x5678...ef01"]
/// ```
/// Where index 0 = nullifier, index 1 = action.
///
/// **Binary:** 64 bytes total (32 bytes nullifier + 32 bytes action), big-endian.
///
/// # Example
/// ```
/// use world_id_primitives::{FieldElement, SessionNullifier};
/// use ruint::aliases::U256;
///
/// let nullifier = FieldElement::from(42u64);
/// let action = FieldElement::from(100u64);
/// let session = SessionNullifier::new(nullifier, action);
///
/// // Get as contract-compatible array
/// let eth_repr: [U256; 2] = session.as_ethereum_representation();
/// assert_eq!(eth_repr[0], U256::from(42));
/// assert_eq!(eth_repr[1], U256::from(100));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionNullifier {
    /// The nullifier value derived from (user, rpId, sessionId).
    nullifier: FieldElement,
    /// The action value bound to this session proof.
    action: FieldElement,
}

impl SessionNullifier {
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
        let nullifier = FieldElement::try_from(value[0])
            .map_err(|e| format!("invalid nullifier: {e}"))?;
        let action = FieldElement::try_from(value[1])
            .map_err(|e| format!("invalid action: {e}"))?;
        Ok(Self { nullifier, action })
    }

    /// Converts to compressed bytes (64 bytes total: 2 x 32 bytes, big-endian).
    #[must_use]
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let repr = self.as_ethereum_representation();
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&repr[0].to_be_bytes::<32>());
        bytes.extend_from_slice(&repr[1].to_be_bytes::<32>());
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

        let nullifier_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let action_bytes: [u8; 32] = bytes[32..].try_into().unwrap();

        let nullifier_u256 = U256::from_be_bytes(nullifier_bytes);
        let action_u256 = U256::from_be_bytes(action_bytes);

        Self::from_ethereum_representation([nullifier_u256, action_u256])
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

// --- Serialization ---

impl Serialize for SessionNullifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON: 2-element array [nullifier, action] matching contract's uint256[2]
            use serde::ser::SerializeTuple;
            let mut tuple = serializer.serialize_tuple(2)?;
            tuple.serialize_element(&self.nullifier)?;
            tuple.serialize_element(&self.action)?;
            tuple.end()
        } else {
            // Binary: compressed bytes
            serializer.serialize_bytes(&self.to_compressed_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for SessionNullifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON: 2-element array [nullifier, action]
            let arr: [FieldElement; 2] = Deserialize::deserialize(deserializer)?;
            Ok(Self {
                nullifier: arr[0],
                action: arr[1],
            })
        } else {
            // Binary: compressed bytes
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::from_compressed_bytes(&bytes).map_err(D::Error::custom)
        }
    }
}

// --- Conversions ---

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

        // Verify JSON is an array format
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));

        // Verify roundtrip
        let decoded: SessionNullifier = serde_json::from_str(&json).unwrap();
        assert_eq!(session, decoded);
    }

    #[test]
    fn test_json_format() {
        let session = SessionNullifier::new(test_field_element(1), test_field_element(2));
        let json = serde_json::to_string(&session).unwrap();

        // Should be a 2-element array [nullifier, action]
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        // Index 0 = nullifier, Index 1 = action
        assert!(arr[0].is_string());
        assert!(arr[1].is_string());
    }

    #[test]
    fn test_compressed_bytes_roundtrip() {
        let session = SessionNullifier::new(test_field_element(1001), test_field_element(42));
        let bytes = session.to_compressed_bytes();

        assert_eq!(bytes.len(), 64); // 32 + 32 bytes

        let decoded = SessionNullifier::from_compressed_bytes(&bytes).unwrap();
        assert_eq!(session, decoded);
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
