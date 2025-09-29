//! The Credential struct.

use ark_ff::{PrimeField, Zero};
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS, POSEIDON2_BN254_T8_PARAMS};
use ruint::aliases::U256;
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

static MAX_CLAIMS: usize = 16;

/// Base representation of a `Credential` in the World ID Protocol.
///
/// A credential is generally a verifiable digital statement about a subject.
///
/// In the case of World ID these statements are about humans, with the most common
/// credentials being Orb verification or document verification.
#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    /// Version representation of this structure
    version: CredentialVersion,
    /// Unique credential type id that is used to lookup of verifying information
    issuer_schema_id: u64,
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
    claims: Vec<BaseField>,
    /// If needed, can be used as commitment to the underlying data.
    /// This can be useful to tie multiple proofs about the same data together.
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    associated_data_hash: BaseField,
}

impl Credential {
    /// Create a new credential.
    pub fn new() -> Self {
        Self {
            version: CredentialVersion::V1,
            issuer_schema_id: 0,
            account_id: 0,
            genesis_issued_at: 0,
            expires_at: 0,
            claims: vec![BaseField::zero(); MAX_CLAIMS],
            associated_data_hash: BaseField::zero(),
        }
    }

    /// Set the version of the credential.
    pub fn version(mut self, version: CredentialVersion) -> Self {
        self.version = version;
        self
    }

    /// Set the issuer schema id of the credential.
    pub fn issuer_schema_id(mut self, issuer_schema_id: u64) -> Self {
        self.issuer_schema_id = issuer_schema_id;
        self
    }

    /// Set the account id of the credential.
    pub fn account_id(mut self, account_id: u64) -> Self {
        self.account_id = account_id;
        self
    }

    /// Set the genesis issued at of the credential.
    pub fn genesis_issued_at(mut self, genesis_issued_at: u64) -> Self {
        self.genesis_issued_at = genesis_issued_at;
        self
    }

    /// Set the expires at of the credential.
    pub fn expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set the claim of the credential.
    pub fn claim(mut self, index: usize, claim: U256) -> Result<Self, anyhow::Error> {
        if index >= self.claims.len() {
            return Err(anyhow::anyhow!("Index of claim out of bounds"));
        }
        self.claims[index] = claim.try_into()?;
        Ok(self)
    }

    /// Set the associated data hash of the credential.
    pub fn associated_data_hash(
        mut self,
        associated_data_hash: U256,
    ) -> Result<Self, anyhow::Error> {
        self.associated_data_hash = associated_data_hash.try_into()?;
        Ok(self)
    }

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
                let hasher = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);
                if self.claims.len() > MAX_CLAIMS {
                    return Err(anyhow::anyhow!(
                        "There can be at most {} claims",
                        MAX_CLAIMS
                    ));
                }
                let mut input = [BaseField::zero(); MAX_CLAIMS];
                input[..self.claims.len()].copy_from_slice(&self.claims);
                hasher.permutation_in_place(&mut input);
                let claims_hash = input[1];

                // Hash the credential
                let hasher = Poseidon2::new(&POSEIDON2_BN254_T8_PARAMS);
                let mut input = [
                    self.get_cred_ds(),
                    self.issuer_schema_id.into(),
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
