//! The Credential struct.

use crate::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use ark_babyjubjub::EdwardsAffine;
use ark_ff::{PrimeField, Zero};
use eyre::bail;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS};
use ruint::aliases::U256;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::types::BaseField;

#[cfg(feature = "authenticator")]
use oprf_client::CredentialsSignature;

/// Version representation of the `Credential` struct
#[derive(Default, Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredentialVersion {
    #[default]
    V1 = 1,
}

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
    /// The signature of the credential.
    #[serde(serialize_with = "serialize_signature")]
    #[serde(deserialize_with = "deserialize_signature")]
    #[serde(default)]
    pub signature: Option<EdDSASignature>,
    /// The issuer of the credential.
    pub issuer: EdDSAPublicKey,
}

impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
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
            signature: None,
            issuer: EdDSAPublicKey {
                pk: EdwardsAffine::default(),
            },
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
    pub fn claim(mut self, index: usize, claim: U256) -> Result<Self, eyre::Error> {
        if index >= self.claims.len() {
            bail!("Index of claim out of bounds");
        }
        self.claims[index] = claim.try_into()?;
        Ok(self)
    }

    /// Set the associated data hash of the credential.
    ///
    /// # Errors
    /// Will error if the provided hash cannot be lowered into the field.
    pub fn associated_data_hash(mut self, associated_data_hash: U256) -> Result<Self, eyre::Error> {
        self.associated_data_hash = associated_data_hash.try_into()?;
        Ok(self)
    }

    /// Get the credential domain separator for the given version.
    #[must_use]
    pub fn get_cred_ds(&self) -> BaseField {
        match self.version {
            CredentialVersion::V1 => {
                BaseField::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ+DLBE-v1")
            } // TODO: change back
        }
    }

    /// Get the claims hash of the credential.
    ///
    /// # Errors
    /// Will error if there are more claims than the maximum allowed.
    /// Will error if the claims cannot be lowered into the field. Should not occur in practice.
    pub fn claims_hash(&self) -> Result<BaseField, eyre::Error> {
        let hasher = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);
        if self.claims.len() > MAX_CLAIMS {
            bail!("There can be at most {MAX_CLAIMS} claims");
        }
        let mut input = [BaseField::zero(); MAX_CLAIMS];
        input[..self.claims.len()].copy_from_slice(&self.claims);
        hasher.permutation_in_place(&mut input);
        Ok(input[1])
    }

    /// Computes the specifically designed hash of the credential for the given version.
    ///
    /// The hash is signed by the issuer to provide authenticity for the credential.
    ///
    /// # Errors
    /// - Will error if there are more claims than the maximum allowed.
    /// - Will error if the claims cannot be lowered into the field. Should not occur in practice.
    pub fn hash(&self) -> Result<BaseField, eyre::Error> {
        match self.version {
            CredentialVersion::V1 => {
                // Hash the credential
                let hasher = Poseidon2::<_, 8, 5>::default();
                let mut input = [
                    self.get_cred_ds(),
                    self.issuer_schema_id.into(),
                    self.account_id.into(),
                    self.genesis_issued_at.into(),
                    self.expires_at.into(),
                    self.claims_hash()?,
                    self.associated_data_hash,
                    BaseField::zero(),
                ];
                hasher.permutation_in_place(&mut input);
                Ok(input[1])
            }
        }
    }

    /// Sign the credential.
    ///
    /// # Errors
    /// Will error if the credential cannot be hashed.
    pub fn sign(mut self, signer: &EdDSAPrivateKey) -> Result<Self, eyre::Error> {
        self.signature = Some(signer.sign(self.hash()?));
        self.issuer = signer.public();
        Ok(self)
    }

    /// Verify the signature of the credential against the issuer public key and expected hash.
    ///
    /// # Errors
    /// Will error if the credential is not signed.
    /// Will error if the credential cannot be hashed.
    pub fn verify_signature(
        &self,
        expected_issuer_pubkey: &EdDSAPublicKey,
    ) -> Result<bool, eyre::Error> {
        if &self.issuer != expected_issuer_pubkey {
            return Err(eyre::eyre!(
                "Issuer public key does not match expected public key"
            ));
        }
        if let Some(signature) = &self.signature {
            return Ok(self.issuer.verify(self.hash()?, signature));
        }
        Err(eyre::eyre!("Credential not signed"))
    }
}

#[cfg(feature = "authenticator")]
impl TryFrom<Credential> for CredentialsSignature {
    type Error = eyre::Error;
    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        Ok(Self {
            type_id: credential.issuer_schema_id.into(),
            issuer: credential.issuer.clone(),
            hashes: [credential.claims_hash()?, credential.associated_data_hash],
            signature: credential
                .signature
                .ok_or_else(|| eyre::eyre!("Credential not signed"))?,
            genesis_issued_at: credential.genesis_issued_at,
            expires_at: credential.expires_at,
        })
    }
}

#[allow(clippy::ref_option)]
fn serialize_signature<S>(
    signature: &Option<EdDSASignature>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let Some(signature) = signature else {
        return serializer.serialize_none();
    };
    let sig = signature
        .to_compressed_bytes()
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&hex::encode(sig))
}

fn deserialize_signature<'de, D>(deserializer: D) -> Result<Option<EdDSASignature>, D::Error>
where
    D: Deserializer<'de>,
{
    let maybe_str = Option::<String>::deserialize(deserializer)?;

    let Some(s) = maybe_str else { return Ok(None) };

    let bytes = hex::decode(s).map_err(de::Error::custom)?;
    if bytes.len() != 64 {
        return Err(de::Error::custom("Invalid signature. Expected 64 bytes."));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    let signature = EdDSASignature::from_compressed_bytes(arr).map_err(de::Error::custom)?;
    Ok(Some(signature))
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

        let issuer_sk = EdDSAPrivateKey::from_bytes([0; 32]);
        let credential = credential.sign(&issuer_sk).unwrap();

        assert_eq!(credential.account_id, 456);
        assert!(credential.signature.is_some());

        let json = serde_json::to_string(&credential).unwrap();

        let parsed: Credential = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&parsed).unwrap();

        assert_eq!(json, json2);

        let issuer_public_key = issuer_sk.public();
        let verified = issuer_public_key.verify(
            credential.hash().unwrap(),
            credential.signature.as_ref().unwrap(),
        );
        assert!(verified);

        let verified = credential.verify_signature(&issuer_public_key).unwrap();
        assert!(verified);
    }
}
