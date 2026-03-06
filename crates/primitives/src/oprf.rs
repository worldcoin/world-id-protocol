use std::str::FromStr;

use ark_bn254::Bn254;
use ark_serde_compat::babyjubjub;
use circom_types::groth16::Proof;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::rp::RpId;

/// A module identifier for OPRF evaluations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OprfModule {
    /// Oprf module for generating nullifiers
    Nullifier,
    /// Oprf module for generating credential blinding factors
    CredentialBlindingFactor,
}

impl std::fmt::Display for OprfModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nullifier => write!(f, "nullifier"),
            Self::CredentialBlindingFactor => write!(f, "credential_blinding_factor"),
        }
    }
}

/// A request sent by a client for OPRF nullifier authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct NullifierOprfRequestAuthV1 {
    /// Zero-knowledge proof provided by the user.
    pub proof: Proof<Bn254>,
    /// The action
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub nonce: ark_babyjubjub::Fq,
    /// The Merkle root associated with this request.
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub merkle_root: ark_babyjubjub::Fq,
    /// The current time stamp (unix secs)
    pub current_time_stamp: u64,
    /// Expiration timestamp of the request (unix secs)
    pub expiration_timestamp: u64,
    /// The RP's signature on the request, see `compute_rp_signature_msg` for details.
    #[serde(deserialize_with = "parse_signature")]
    pub signature: alloy_primitives::Signature,
    /// The `rp_id`
    pub rp_id: RpId,
}

/// A request sent by a client for OPRF credential blinding factor authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialBlindingFactorOprfRequestAuthV1 {
    /// Zero-knowledge proof provided by the user.
    pub proof: Proof<Bn254>,
    /// The action
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub nonce: ark_babyjubjub::Fq,
    /// The Merkle root associated with this request.
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub merkle_root: ark_babyjubjub::Fq,
    /// The `issuer_schema_id` in the `CredentialSchemaIssuerRegistry` contract
    pub issuer_schema_id: u64,
}

/// Temporary signature parser that accepts raw serialized `alloy_primitives::Signature` from its own
/// serde implementation **and** the new hex string format we are introducing in [`crate::serde_utils::hex_signature`].
///
/// TODO: After full roll-out in new OPRF nodes version, this can be removed.
fn parse_signature<'de, D>(deserializer: D) -> Result<alloy_primitives::Signature, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match &value {
        serde_json::Value::String(s) => {
            alloy_primitives::Signature::from_str(s).map_err(D::Error::custom)
        }
        _ => serde_json::from_value(value).map_err(D::Error::custom),
    }
}

/// Temporary tests for [`parse_signature`]
#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::Signature;
    use ruint::aliases::U256;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct WithSig {
        #[serde(deserialize_with = "parse_signature")]
        signature: Signature,
    }

    #[test]
    fn parse_signature_accepts_both_formats() {
        let sig = Signature::new(U256::from(1), U256::from(2), false);

        // New format: plain 0x-prefixed hex string
        let hex_str = sig.to_string();
        let new_fmt = format!(r#"{{"signature":"{hex_str}"}}"#);
        let parsed: WithSig = serde_json::from_str(&new_fmt).expect("new hex format should parse");
        assert_eq!(parsed.signature, sig);

        // Old format: alloy's native serde (JSON object with r, s, yParity)
        let native_json = serde_json::to_string(&sig).expect("native serde should serialize");
        let old_fmt = format!(r#"{{"signature":{native_json}}}"#);
        let parsed: WithSig =
            serde_json::from_str(&old_fmt).expect("old native serde format should parse");
        assert_eq!(parsed.signature, sig);
    }
}
