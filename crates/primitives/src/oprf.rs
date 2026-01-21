use ark_bn254::Bn254;
use ark_serde_compat::babyjubjub;
use circom_types::groth16::Proof;
use serde::{Deserialize, Serialize};

use crate::rp::RpId;

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct OprfRequestAuthV1 {
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
    /// The signature of the nonce || action || timestamp
    pub signature: alloy_primitives::Signature,
    /// The `rp_id`
    pub rp_id: RpId,
}
