//! # v1 API types
//!
//! Data transfer objects for the version 1 OPRF API.
//!
//! This module defines the request and response payloads exchanged
//! between clients and the server for the OPRF protocol, along with
//! identifiers used to reference keys and epochs. Types here wrap
//! cryptographic proofs and points with Serde (de)serialization so
//! they can be sent over the wire.

use ark_serde_compat::babyjubjub;
use circom_types::{ark_bn254::Bn254, groth16::Proof};
use eddsa_babyjubjub::EdDSAPublicKey;
use serde::{Deserialize, Serialize};

use crate::MerkleRoot;

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct OprfRequestAuth {
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
    pub merkle_root: MerkleRoot,
    /// The credential public key
    pub cred_pk: EdDSAPublicKey, // TODO maybe remove and get from chain
    /// The current time stamp (unix secs)
    pub current_time_stamp: u64,
    /// The signature of the nonce || timestamp
    pub signature: k256::ecdsa::Signature,
}
