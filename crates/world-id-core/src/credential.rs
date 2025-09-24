//! The Credential struct.

use ark_bn254::Fr;
use serde::{Deserialize, Serialize};

/// Version representation of the `Credential` struct
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredentialVersion {
    V1 = 1,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)] // TODO: Remove once in use
pub struct Credential {
    /// Version representation of this structure
    version: CredentialVersion,
    /// Unique credential type id that is used to lookup of verifying information
    credential_type_id: u64,
    /// World ID to which the credential is issued. This ID comes from the `AccountRegistry`.
    account_id: u64,
    /// Timestamp of first issuance of this credential (unix seconds)
    genesis_issued_at: u64,
    /// Expiration timestamp (unix seconds)
    expires_at: u64,
    /// These are concrete statements that the issuer attests about the receiver.
    /// Could be just commitments to data (e.g. passport image) or
    /// the value directly (e.g. date of birth)
    // TODO: claims: [Fr; 16],
    /// If needed, can be used as commitment to the underlying data.
    /// This can be useful to tie multiple proofs about the same data together.
    // TODO: associated_data_hash: Fr,
}
