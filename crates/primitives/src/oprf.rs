use ark_bn254::Bn254;
use ark_serde_compat::babyjubjub;
use circom_types::groth16::Proof;
use serde::{Deserialize, Serialize};

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
    #[serde(with = "crate::serde_utils::hex_signature")]
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
