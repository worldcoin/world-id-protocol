//! The Credential struct.

use ark_ff::{PrimeField, Zero};
use poseidon2::{Poseidon2, POSEIDON2_BN254_T8_PARAMS};
use serde::{Deserialize, Serialize};

/// Version representation of the `Credential` struct
#[derive(Default, Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredentialVersion {
    #[default]
    V1 = 1,
}

/// The base field for the credential.
pub type BaseField = ark_babyjubjub::Fq;
/// Claims are the concrete statements that the issuer attests about the receiver.
pub type Claims = Vec<BaseField>;

/// Base representation of a `Credential` in the World ID Protocol.
///
/// A credential is generally a verifiable digital statement about a subject.
///
/// In the case of World ID these statements are about humans, with the most common
/// credentials being Orb verification or document verification.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// Version representation of this structure
    version: CredentialVersion,
    /// Unique credential type id that is used to lookup of verifying information
    type_id: u64,
    /// World ID to which the credential is issued. This ID comes from the `AccountRegistry`.
    account_id: u64,
    /// Timestamp of first issuance of this credential (unix seconds)
    genesis_issued_at: u64,
    /// Expiration timestamp (unix seconds)
    expires_at: u64,
    /// These are concrete statements that the issuer attests about the receiver.
    /// Could be just commitments to data (e.g. passport image) or
    /// the value directly (e.g. date of birth)
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base_sequence")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base_sequence")]
    claims: Claims,
    /// If needed, can be used as commitment to the underlying data.
    /// This can be useful to tie multiple proofs about the same data together.
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    associated_data_hash: BaseField,
}

impl Credential {
    /// Get the credential domain separator for the given version.
    pub fn get_cred_ds(&self) -> BaseField {
        match self.version {
            CredentialVersion::V1 => {
                BaseField::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ+DLBE-v1")
            }
        }
    }

    /// Hash the credential.
    pub fn hash(&self) -> Result<BaseField, anyhow::Error> {
        match self.version {
            CredentialVersion::V1 => {
                // Hash the claims
                let hasher = Poseidon2::new(&POSEIDON2_BN254_T8_PARAMS);
                if self.claims.len() != 8 {
                    return Err(anyhow::anyhow!("Claims must be 8 elements"));
                }
                let mut input = self.claims.as_slice().try_into().unwrap();
                hasher.permutation_in_place(&mut input);
                let claims_hash = input[1];

                // Hash the credential
                let mut input = [
                    self.get_cred_ds(),
                    self.type_id.into(),
                    self.account_id.into(),
                    self.genesis_issued_at.into(),
                    self.expires_at.into(),
                    claims_hash,
                    self.associated_data_hash,
                    BaseField::zero(),
                ];
                hasher.permutation_in_place(&mut input);
                Ok(input[1])
            }
        }
    }
}