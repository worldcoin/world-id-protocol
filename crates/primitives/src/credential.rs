use ark_babyjubjub::EdwardsAffine;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use rand::Rng;
use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{FieldElement, PrimitiveError, sponge::hash_bytes_to_field_element};

/// Domain separation tag to avoid collisions with other Poseidon2 usages.
const ASSOCIATED_DATA_HASH_DS_TAG: &[u8] = b"ASSOCIATED_DATA_HASH_V1";
const CLAIMS_HASH_DS_TAG: &[u8] = b"CLAIMS_HASH_V1";

/// Version of the `Credential` object
#[derive(Default, Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredentialVersion {
    /// Version 1 of the `Credential`. In addition to the specific attributes,
    /// - Hashing function: `Poseidon2`
    /// - Signature scheme: `EdDSA` on `BabyJubJub` Curve
    /// - Curve (Base) Field (`Fq`): `BabyJubJub` Curve Field (also the BN254 Scalar Field)
    /// - Scalar Field (`Fr`): `BabyJubJub` Scalar Field
    #[default]
    V1 = 1,
}

/// Base representation of a `Credential` in the World ID Protocol.
///
/// A credential is generally a verifiable digital statement about a subject. It is
/// the canonical object: everything a verifier needs for proofs and authorization.
///
/// In the case of World ID these statements are about humans, with the most common
/// credentials being Orb verification or document verification.
///
/// # Associated Data
///
/// Credentials have a pre-defined strict structure, which is determined by their version. Extending this,
/// issuers may opt to include additional arbitrary data with the Credential. This data is called
/// **Associated Data**.
/// - Associated data is stored by Authenticators with the Credential.
/// - Including associated data is a decision by the issuer. Its structure and content is solely
///   determined by the issuer and the data will not be exposed to RPs or others.
/// - An example of associated data use is supporting data to re-issue a credential (e.g. a sign up number).
/// - Associated data is never exposed to RPs or others. It only lives in the Authenticator.
/// - Associated data is authenticated in the Credential through the `associated_data_hash` field. The issuer
///   can determine how this data is hashed. However providing the raw data to `associated_data` can ensure a
///   consistent hashing into the field.
/// ```text
/// +------------------------------+
/// |          Credential          |
/// |                              |
/// |  - associated_data_hash <----+
/// |  - signature                 |
/// +------------------------------+
///           ^
///           |
///     Hash(associated_data)
///           |
/// Associated Data
/// +------------------------------+
/// | Optional arbitrary data      |
/// +------------------------------+
/// ```
///
/// # Design Principles:
/// - A credential clearly separates:
///    - **Assertion** (the claim being made)
///    - **Issuer** (who attests to it / vouches for it)
///    - **Subject** (who it is about)
///    - **Presenter binding** (who can present it)
/// - Credentials are **usable across authenticators** without leaking correlate-able identifiers to RPs.
/// - Revocation, expiry, and re-issuance are **first-class lifecycle properties**.
/// - Flexibility: credentials may take different formats but share **common metadata** (validity, issuer, trust, type).
///
/// All credentials have an issuer and schema, identified with the `issuer_schema_id` field. This identifier
/// is registered in the `CredentialSchemaIssuerRegistry` contract. It represents a particular schema issued by
/// a particular issuer. Some schemas are intended to be global (e.g. representing an ICAO-compliant passport) and
/// some issuer-specific. Schemas should be registered in the `CredentialSchemaIssuerRegistry` contract and should be
/// publicly accessible.
///
/// We want to encourage schemas to be widely distributed and adopted. If everyone uses the same passport schema,
/// for example, the Protocol will have better interoperability across passport credential issuers, reducing the
/// burden on holders (to make sense of which passport they have), and similarly, RPs.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    /// A reference identifier for the credential. This can be used by issuers
    /// to manage credential lifecycle.
    ///
    /// - This ID is never exposed or used outside of issuer scope. It is never part of proofs
    ///   or exposed to RPs.
    /// - Generally, it is recommended to maintain the default of a random identifier.
    ///
    /// # Example Uses
    /// - Track issued credentials to later support revocation after refreshing.
    pub id: u64,
    /// The version of the Credential determines its structure.
    pub version: CredentialVersion,
    /// Unique issuer schema id represents the unique combination of the credential's
    /// schema and the issuer.
    ///
    /// The `issuer_schema_id` is registered in the `CredentialSchemaIssuerRegistry`. With this
    /// identifier, the RPs lookup the authorized keys that can sign the credential.
    pub issuer_schema_id: u64,
    /// The blinded subject (World ID) for which the credential is issued.
    ///
    /// The underlying identifier comes from the `WorldIDRegistry` and is
    /// the `leaf_index` of the World ID on the Merkle tree. However, this is blinded
    /// for each `issuer_schema_id` with a blinding factor to prevent correlation of credentials
    /// by malicious issuers.
    pub sub: FieldElement,
    /// Timestamp of **first issuance** of this credential (unix seconds), i.e. this represents when the holder
    /// first obtained the credential. Even if the credential has been issued multiple times (e.g. because of a renewal),
    /// this timestamp should stay constant.
    ///
    /// This timestamp can be queried (only as a minimum value) by RPs.
    pub genesis_issued_at: u64,
    /// Expiration timestamp (unix seconds)
    pub expires_at: u64,
    /// **For Future Use**. Concrete statements that the issuer attests about the receiver.
    ///
    /// They can be just commitments to data (e.g. passport image) or
    /// the value directly (e.g. date of birth).
    ///
    /// Currently these statements are not in use in the Proofs yet.
    pub claims: Vec<FieldElement>,
    /// The commitment to the associated data issued with the Credential.
    ///
    /// By default this uses the internal `hash_bytes_to_field_element` function,
    /// but each issuer may determine their own hashing algorithm.
    ///
    /// This hash is generally only used by the issuer.
    pub associated_data_hash: FieldElement,
    /// The signature of the credential (signed by the issuer's key)
    #[serde(serialize_with = "serialize_signature")]
    #[serde(deserialize_with = "deserialize_signature")]
    #[serde(default)]
    pub signature: Option<EdDSASignature>,
    /// The public component of the issuer's key which signed the Credential.
    pub issuer: EdDSAPublicKey,
}

impl Credential {
    /// The maximum number of claims that can be included in a credential.
    pub const MAX_CLAIMS: usize = 16;

    /// Initializes a new credential.
    ///
    /// Note default fields occupy a sentinel value of `BaseField::zero()`
    #[must_use]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            id: rng.r#gen(),
            version: CredentialVersion::V1,
            issuer_schema_id: 0,
            sub: FieldElement::ZERO,
            genesis_issued_at: 0,
            expires_at: 0,
            claims: vec![FieldElement::ZERO; Self::MAX_CLAIMS],
            associated_data_hash: FieldElement::ZERO,
            signature: None,
            issuer: EdDSAPublicKey {
                pk: EdwardsAffine::default(),
            },
        }
    }

    /// Set the `id` of the credential.
    #[must_use]
    pub const fn id(mut self, id: u64) -> Self {
        self.id = id;
        self
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

    /// Set the `sub` for the credential computed from `leaf_index` and a `blinding_factor`.
    #[must_use]
    pub fn sub(mut self, leaf_index: U256, blinding_factor: FieldElement) -> Self {
        let mut input = [
            *self.get_sub_ds(),
            leaf_index
                .try_into()
                .expect("leaf_index must always fit in field"),
            *blinding_factor,
        ];
        poseidon2::bn254::t3::permutation_in_place(&mut input);
        self.sub = input[1].into();
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

    /// Set a claim hash for the credential at an index.
    ///
    /// # Errors
    /// Will error if the index is out of bounds.
    pub fn claim_hash(mut self, index: usize, claim: U256) -> Result<Self, PrimitiveError> {
        if index >= self.claims.len() {
            return Err(PrimitiveError::OutOfBounds);
        }
        self.claims[index] = claim.try_into().map_err(|_| PrimitiveError::NotInField)?;
        Ok(self)
    }

    /// Set the claim hash at specific index by hashing arbitrary bytes using Poseidon2.
    ///
    /// This method accepts arbitrary bytes, converts them to field elements,
    /// applies a Poseidon2 hash, and stores the result as claim at the provided index.
    ///
    /// # Arguments
    /// * `claim` - Arbitrary bytes to hash (any length).
    ///
    /// # Errors
    /// Will error if the data is empty and if the index is out of bounds.
    pub fn claim(mut self, index: usize, claim: &[u8]) -> Result<Self, PrimitiveError> {
        if index >= self.claims.len() {
            return Err(PrimitiveError::OutOfBounds);
        }
        self.claims[index] = hash_bytes_to_field_element(CLAIMS_HASH_DS_TAG, claim)?;
        Ok(self)
    }
    /// Set the associated data hash of the credential from a pre-computed hash.
    ///
    /// # Errors
    /// Will error if the provided hash cannot be lowered into the field.
    pub fn associated_data_hash(
        mut self,
        associated_data_hash: U256,
    ) -> Result<Self, PrimitiveError> {
        self.associated_data_hash = associated_data_hash
            .try_into()
            .map_err(|_| PrimitiveError::NotInField)?;
        Ok(self)
    }

    /// Set the associated data hash by hashing arbitrary bytes using Poseidon2.
    ///
    /// This method accepts arbitrary bytes, converts them to field elements,
    /// applies a Poseidon2 hash, and stores the result as the associated data hash.
    ///
    /// # Arguments
    /// * `data` - Arbitrary bytes to hash (any length).
    ///
    /// # Errors
    /// Will error if the data is empty.
    pub fn associated_data(mut self, data: &[u8]) -> Result<Self, PrimitiveError> {
        self.associated_data_hash = hash_bytes_to_field_element(ASSOCIATED_DATA_HASH_DS_TAG, data)?;
        Ok(self)
    }

    /// Get the credential domain separator for the given version.
    #[must_use]
    pub fn get_cred_ds(&self) -> FieldElement {
        match self.version {
            CredentialVersion::V1 => FieldElement::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ"),
        }
    }

    /// Get the sub domain separator for the given version.
    #[must_use]
    pub fn get_sub_ds(&self) -> FieldElement {
        match self.version {
            CredentialVersion::V1 => FieldElement::from_be_bytes_mod_order(b"H_CS(id, r)"),
        }
    }

    /// Get the claims hash of the credential.
    ///
    /// # Errors
    /// Will error if there are more claims than the maximum allowed.
    /// Will error if the claims cannot be lowered into the field. Should not occur in practice.
    pub fn claims_hash(&self) -> Result<FieldElement, eyre::Error> {
        if self.claims.len() > Self::MAX_CLAIMS {
            eyre::bail!("There can be at most {} claims", Self::MAX_CLAIMS);
        }
        let mut input = [*FieldElement::ZERO; Self::MAX_CLAIMS];
        for (i, claim) in self.claims.iter().enumerate() {
            input[i] = **claim;
        }
        poseidon2::bn254::t16::permutation_in_place(&mut input);
        Ok(input[1].into())
    }

    // Computes the specifically designed hash of the credential for the given version.
    ///
    /// The hash is signed by the issuer to provide authenticity for the credential.
    ///
    /// # Errors
    /// - Will error if there are more claims than the maximum allowed.
    /// - Will error if the claims cannot be lowered into the field. Should not occur in practice.
    pub fn hash(&self) -> Result<FieldElement, eyre::Error> {
        match self.version {
            CredentialVersion::V1 => {
                let mut input = [
                    *self.get_cred_ds(),
                    self.issuer_schema_id.into(),
                    *self.sub,
                    self.genesis_issued_at.into(),
                    self.expires_at.into(),
                    *self.claims_hash()?,
                    *self.associated_data_hash,
                    self.id.into(),
                ];
                poseidon2::bn254::t8::permutation_in_place(&mut input);
                Ok(input[1].into())
            }
        }
    }

    /// Sign the credential.
    ///
    /// # Errors
    /// Will error if the credential cannot be hashed.
    pub fn sign(self, signer: &EdDSAPrivateKey) -> Result<Self, eyre::Error> {
        let mut credential = self;
        credential.signature = Some(signer.sign(*credential.hash()?));
        credential.issuer = signer.public();
        Ok(credential)
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
            return Ok(self.issuer.verify(*self.hash()?, signature));
        }
        Err(eyre::eyre!("Credential not signed"))
    }
}

impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializes the signature as compressed bytes (encoding r and s concatenated)
/// where `r` is compressed to a single coordinate. Result is hex-encoded.
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

    #[test]
    fn test_associated_data_matches_direct_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Using the associated_data method
        let credential = Credential::new().associated_data(&data).unwrap();

        // Using the hash function directly
        let direct_hash = hash_bytes_to_field_element(ASSOCIATED_DATA_HASH_DS_TAG, &data).unwrap();

        // Both should produce the same hash
        assert_eq!(credential.associated_data_hash, direct_hash);
    }

    #[test]
    fn test_associated_data_method() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        let credential = Credential::new().associated_data(&data).unwrap();

        // Should have a non-zero associated data hash
        assert_ne!(credential.associated_data_hash, FieldElement::ZERO);
    }

    #[test]
    fn test_claim_matches_direct_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Using the claim method
        let credential = Credential::new().claim(0, &data).unwrap();

        // Using the hash function directly
        let direct_hash = hash_bytes_to_field_element(CLAIMS_HASH_DS_TAG, &data).unwrap();

        // Both should produce the same hash
        assert_eq!(credential.claims[0], direct_hash);
    }

    #[test]
    fn test_claim_method() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        let credential = Credential::new().claim(1, &data).unwrap();

        // Should have a non-zero claim hash
        assert_ne!(credential.claims[1], FieldElement::ZERO);
    }
}
