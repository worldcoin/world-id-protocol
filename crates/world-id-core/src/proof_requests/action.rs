use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Actions are defined by relying parties and represent the unit of uniqueness for proofs
/// (e.g. one-time signup, daily claim, per-season reward). Together with the RP ID,
/// the Action ID is a public input to nullifier generation, ensuring each user can only
/// perform the specified action under the intended constraints while remaining anonymous.
/// Action identifiers are encoded as `act_`-prefixed base64 JSON structures.
/// TODO - link to public docs when available
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Action {
    /// The timestamp when the action will expire (seconds since epoch)
    pub expires_at: u64,
    /// Arbitrary data to be included. Typically, a UTF-8 string encoded to bytes.
    pub data: Vec<u8>,
    /// Description shown to the user when they are prompted to perform the action
    pub description: String,
}

impl Action {
    /// Encode to `act_`-prefixed base64 JSON representation
    ///
    /// # Panics
    /// Panics only if serialization of `Action` to JSON fails, which should not occur
    /// for well-formed values as `Action` derives `Serialize`.
    #[must_use]
    pub fn encode(&self) -> String {
        let json_bytes = serde_json::to_vec(self).expect("Action serializes");
        let b64 = BASE64_URL_SAFE_NO_PAD.encode(&json_bytes);
        format!("act_{b64}")
    }

    /// Decode from `act_...` string form
    ///
    /// # Errors
    /// Returns an error if the input is missing the `act_` prefix, contains invalid
    /// base64, or the decoded bytes are not valid JSON for an `Action`.
    pub fn decode(encoded: &str) -> Result<Self, ActionDecodeError> {
        let rest = encoded
            .strip_prefix("act_")
            .ok_or(ActionDecodeError::MissingPrefix)?;
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(ActionDecodeError::Base64)?;
        let action: Self = serde_json::from_slice(&bytes).map_err(ActionDecodeError::Json)?;
        Ok(action)
    }

    /// Compute SHA-256(expires_at_be_u64 || data)
    ///
    /// # Errors
    /// Returns an error if `encoded` is not a valid `Action` per [`Action::decode`].
    pub fn hash_input_bytes(encoded: &str) -> Result<Vec<u8>, ActionDecodeError> {
        let action = Self::decode(encoded)?;
        let mut hasher = Sha256::new();
        hasher.update(action.expires_at.to_be_bytes());
        hasher.update(&action.data);
        Ok(hasher.finalize().to_vec())
    }
}

/// Errors that can occur while decoding an `Action`.
#[derive(Debug, thiserror::Error)]
pub enum ActionDecodeError {
    /// Missing `act_` prefix on the encoded string
    #[error("missing act_ prefix")]
    MissingPrefix,
    /// Invalid base64 content in the encoded payload
    #[error("invalid base64: {0}")]
    Base64(base64::DecodeError),
    /// Invalid JSON content inside the decoded payload
    #[error("invalid json: {0}")]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_roundtrip_and_hash_bytes() {
        let action = Action {
            expires_at: 1_700_000_000,
            data: b"hello".to_vec(),
            description: "Test".to_string(),
        };
        let enc = action.encode();
        assert!(enc.starts_with("act_"));
        let dec = Action::decode(&enc).unwrap();
        assert_eq!(dec, action);

        let bytes = Action::hash_input_bytes(&enc).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(action.expires_at.to_be_bytes());
        hasher.update(&action.data);
        let expected = hasher.finalize().to_vec();
        assert_eq!(bytes, expected);
    }
}
