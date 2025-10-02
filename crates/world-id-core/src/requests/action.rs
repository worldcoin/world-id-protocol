use base64::engine::general_purpose::STANDARD;
use base64::prelude::{BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD};
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

impl WorldIdAction {
    /// Encode to `act_`-prefixed base64 JSON representation
    #[must_use]
    pub fn encode(&self) -> String {
        let json_bytes = serde_json::to_vec(self).expect("WorldIdAction serializes");
        let b64 = BASE64_URL_SAFE_NO_PAD.encode(&json_bytes);
        format!("act_{}", b64)
    }

    /// Decode from `act_...` string form
    pub fn decode(encoded: &str) -> Result<Self, ActionDecodeError> {
        let rest = encoded
            .strip_prefix("act_")
            .ok_or(ActionDecodeError::MissingPrefix)?;
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(ActionDecodeError::Base64)?;
        let action: WorldIdAction =
            serde_json::from_slice(&bytes).map_err(ActionDecodeError::Json)?;
        Ok(action)
    }

    /// Compute SHA-256(expires_at_be_u64 || data)
    pub fn hash_input_bytes(encoded: &str) -> Result<Vec<u8>, ActionDecodeError> {
        let action = Self::decode(encoded)?;
        let mut hasher = Sha256::new();
        hasher.update(action.expires_at.to_be_bytes());
        hasher.update(&action.data);
        Ok(hasher.finalize().to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActionDecodeError {
    #[error("missing act_ prefix")]
    MissingPrefix,
    #[error("invalid base64: {0}")]
    Base64(base64::DecodeError),
    #[error("invalid json: {0}")]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_roundtrip_and_hash_bytes() {
        let action = WorldIdAction {
            expires_at: 1_700_000_000,
            data: b"hello".to_vec(),
            description: "Test".to_string(),
        };
        let enc = action.encode();
        assert!(enc.starts_with("act_"));
        let dec = WorldIdAction::decode(&enc).unwrap();
        assert_eq!(dec, action);

        let bytes = WorldIdAction::hash_input_bytes(&enc).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(action.expires_at.to_be_bytes());
        hasher.update(&action.data);
        let expected = hasher.finalize().to_vec();
        assert_eq!(bytes, expected);
    }
}
