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
pub type BaseField = ark_bn254::Fr;

static MAX_CLAIMS: usize = 16;

/// Base representation of a `Credential` in the World ID Protocol.
///
/// A credential is generally a verifiable digital statement about a subject.
///
/// In the case of World ID these statements are about humans, with the most common
/// credentials being Orb verification or document verification.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    /// Version representation of this structure
    pub version: CredentialVersion,
    /// Unique credential type id that is used to lookup of verifying information
    pub issuer_schema_id: u64,
    /// World ID to which the credential is issued. This ID comes from the `AccountRegistry`.
    pub account_id: u64,
    /// Timestamp of **first issuance** of this credential (unix seconds), i.e. this represents when the holder
    /// first obtained the credential. Even if the credential has been issued multiple times (e.g. because of a renewal),
    /// this timestamp should stay constant.
    pub genesis_issued_at: u64,
    /// Expiration timestamp (unix seconds)
    pub expires_at: u64,
    /// These are concrete statements that the issuer attests about the receiver.
    /// Could be just commitments to data (e.g. passport image) or
    /// the value directly (e.g. date of birth)
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base_sequence")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base_sequence")]
    pub claims: Vec<BaseField>,
    /// If needed, can be used as commitment to the underlying data.
    /// This can be useful to tie multiple proofs about the same data together.
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    pub associated_data_hash: BaseField,
    /// The signature or other verifying information provided by the issuer.
    ///
    /// By default this is the `EdDSA` signature over the hash of the credential (by the issuer's key registered in the `CredentialSchemaIssuerRegistry`),
    /// but this is not required. The issuer may choose to provide verifying information such that the credential can be verified
    /// using a smart contract (with EIP-1271), support coming in the next iteration of the circuit.
    pub signature: Vec<u8>,
}

impl Credential {
    /// Initializes a new credential.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: CredentialVersion::V1,
            issuer_schema_id: 0,
            account_id: 0,
            genesis_issued_at: 0,
            expires_at: 0,
            claims: vec![BaseField::zero(); MAX_CLAIMS],
            associated_data_hash: BaseField::zero(),
            signature: vec![],
        }
    }

    /// Set the `version` of the credential.
    #[must_use]
    pub const fn version(mut self, version: CredentialVersion) -> Self {
        self.version = version;
        self
    }

    /// Set the `issuerSchemaId` of the credential.
    #[must_use]
    pub const fn issuer_schema_id(mut self, issuer_schema_id: u64) -> Self {
        self.issuer_schema_id = issuer_schema_id;
        self
    }

    /// Set the `accountId` of the credential.
    #[must_use]
    pub const fn account_id(mut self, account_id: u64) -> Self {
        self.account_id = account_id;
        self
    }

    /// Set the genesis issued at of the credential.
    #[must_use]
    pub const fn genesis_issued_at(mut self, genesis_issued_at: u64) -> Self {
        self.genesis_issued_at = genesis_issued_at;
        self
    }

    /// Set the expires at of the credential.
    #[must_use]
    pub const fn expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set a claim for the credential at an index.
    ///
    /// # Errors
    /// Will error if the index is out of bounds.
    pub fn claim(mut self, index: usize, claim: U256) -> Result<Self, anyhow::Error> {
        if index >= self.claims.len() {
            return Err(anyhow::anyhow!("Index of claim out of bounds"));
        }
        self.claims[index] = claim.try_into()?;
        Ok(self)
    }

    /// Set the associated data hash of the credential.
    ///
    /// # Errors
    /// Will error if the provided hash cannot be lowered into the field.
    pub fn associated_data_hash(
        mut self,
        associated_data_hash: U256,
    ) -> Result<Self, anyhow::Error> {
        self.associated_data_hash = associated_data_hash.try_into()?;
        Ok(self)
    }

    /// Set the signature of the credential.
    #[must_use]
    pub fn signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Get the credential domain separator for the given version.
    #[must_use]
    pub fn get_cred_ds(&self) -> BaseField {
        match self.version {
            CredentialVersion::V1 => BaseField::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ"),
        }
    }

    /// Computes the specifically designed hash of the credential for the given version.
    ///
    /// The hash is signed by the issuer to provide authenticity for the credential.
    ///
    /// # Errors
    /// - Will error if there are more claims than the maximum allowed.
    /// - Will error if the claims cannot be lowered into the field. Should not occur in practice.
    pub fn hash(&self) -> Result<BaseField, anyhow::Error> {
        match self.version {
            CredentialVersion::V1 => {
                // Hash the claims
                let hasher = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);
                if self.claims.len() > MAX_CLAIMS {
                    return Err(anyhow::anyhow!("There can be at most {MAX_CLAIMS} claims",));
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

impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unreadable_literal)]
    #[test]
    fn test_credential_builder_and_json_export() {
        let credential = Credential::new()
            .version(CredentialVersion::V1)
            .issuer_schema_id(123)
            .account_id(456)
            .genesis_issued_at(1234567890)
            .expires_at(1234567890 + 86_400)
            .claim(0, U256::from(999))
            .unwrap()
            .associated_data_hash(U256::from(42))
            .unwrap();

        let signature: U256 = credential.hash().unwrap().into();
        let signature = signature + U256::from(1);
        let signature: [u8; 32] = signature.to_be_bytes();
        let credential = credential.signature(signature.to_vec());

        assert_eq!(credential.account_id, 456);
        assert_eq!(credential.signature.len(), 32);

        let json = serde_json::to_string_pretty(&credential).unwrap();

        let parsed: Credential = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string_pretty(&parsed).unwrap();

        assert_eq!(json, json2);
    }
}
