use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// Action payload encoded/decoded per authenticator.mdx
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorldIdAction {
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
        let b64 = STANDARD.encode(&json_bytes);
        format!("act_{}", b64)
    }

    /// Decode from `act_...` string form
    pub fn decode(encoded: &str) -> Result<Self, ActionDecodeError> {
        let rest = encoded
            .strip_prefix("act_")
            .ok_or(ActionDecodeError::MissingPrefix)?;
        let bytes = STANDARD.decode(rest).map_err(ActionDecodeError::Base64)?;
        let action: WorldIdAction =
            serde_json::from_slice(&bytes).map_err(ActionDecodeError::Json)?;
        Ok(action)
    }

    /// Get the raw bytes used for hashing in proofs (base64-decoded JSON bytes)
    pub fn hash_input_bytes(encoded: &str) -> Result<Vec<u8>, ActionDecodeError> {
        let rest = encoded
            .strip_prefix("act_")
            .ok_or(ActionDecodeError::MissingPrefix)?;
        let bytes = STANDARD.decode(rest).map_err(ActionDecodeError::Base64)?;
        Ok(bytes)
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
