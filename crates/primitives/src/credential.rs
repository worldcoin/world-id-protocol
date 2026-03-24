use ark_babyjubjub::EdwardsAffine;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use rand::Rng;
use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{FieldElement, PrimitiveError, sponge::hash_bytes_to_field_element};

/// Domain separation tag to avoid collisions with other Poseidon2 usages.
const ASSOCIATED_DATA_COMMITMENT_DS_TAG: &[u8] = b"ASSOCIATED_DATA_HASH_V1";
const CLAIMS_HASH_DS_TAG: &[u8] = b"CLAIMS_HASH_V1";
const SUB_DS_TAG: &[u8] = b"H_CS(id, r)";

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
/// # Credential Lifecycle
///
/// The following official terminology is defined for the lifecycle of a Credential.
/// - **Issuance** (can also be called **Enrollment**): Process by which a credential is initially issued to a user.
/// - **Renewal**: Process by which a user requests a new Credential from a previously existing active or
///   expired Credential. This usually happens close to Credential expiration. _It is analogous to
///   when you request a renewal of your passport, you get a new passport with a new expiration date._
/// - **Re-Issuance**: Process by which a user obtains a copy of their existing Credential. The copy does not
///   need to be exact, but the original expiration date MUST be preserved. This usually occurs when a user
///   accidentally lost their Credential (e.g. disk failure, authenticator loss) and needs to recover for an existing period.
///
/// # Associated Data
///
/// Credentials have a pre-defined strict structure, which is determined by their version. Issuers
/// may opt to include additional arbitrary data with the Credential (**Associated Data**). This arbitrary data
/// can be used to support the issuer in the operation of their Credential (for example it may contain an identifier
/// to allow credential refresh).
///
/// - Associated data is stored by Authenticators with the Credential.
/// - Introducing associated data is a decision by the issuer. Its structure and content is solely
///   determined by the issuer and the data will not be exposed to RPs or others.
/// - An example of associated data use is supporting data to re-issue a credential (e.g. a sign up number).
/// - Associated data is never exposed to RPs or others. It only lives in the Authenticator and may be provided
///   to issuers.
/// - Associated data is authenticated in the Credential through the `associated_data_commitment` field. The issuer
///   MUST determine how this commitment is computed. Issuers may opt to use the [`Credential::associated_data_commitment_from_raw_bytes`]
///   helper to ensure their raw data is committed, but other commitment mechanisms may make sense depending on the
///   structure of the associated data.
///
/// ```text
/// +------------------------------------+
/// |          Credential                |
/// |                                    |
/// |  - associated_data_commitment <----+
/// |  - signature                       |
/// +------------------------------------+
///               ^
///               |
///     Commitment(associated_data)
///               |
/// Associated Data
/// +------------------------------------+
/// | Optional arbitrary data            |
/// +------------------------------------+
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
    /// The commitment to the Associated Data issued with the Credential.
    ///
    /// This may use a common hashing algorithm from the raw bytes of the
    /// asscociated data and one function is exposed for this convenience,
    /// [`hash_bytes_to_field_element`]. Each issuer however determines how
    /// best to construct this value to establish the integrity of their Associated Data.
    ///
    /// This commitment is only for issuer use.
    #[serde(alias = "associated_data_hash")]
    // this was previously named `associated_data_hash`; fallback will be removed in the next version
    pub associated_data_commitment: FieldElement,
    /// The signature of the credential (signed by the issuer's key)
    #[serde(serialize_with = "serialize_signature")]
    #[serde(deserialize_with = "deserialize_signature")]
    #[serde(default)]
    pub signature: Option<EdDSASignature>,
    /// The public component of the issuer's key which signed the Credential.
    #[serde(serialize_with = "serialize_public_key")]
    #[serde(deserialize_with = "deserialize_public_key")]
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
            associated_data_commitment: FieldElement::ZERO,
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

    /// Set the `sub` for the credential.
    #[must_use]
    pub const fn subject(mut self, sub: FieldElement) -> Self {
        self.sub = sub;
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

    /// Set the associated data commitment of the credential.
    ///
    /// # Errors
    /// Will error if the provided hash cannot be lowered into the field.
    pub fn associated_data_commitment(
        mut self,
        associated_data_commitment: U256,
    ) -> Result<Self, PrimitiveError> {
        self.associated_data_commitment = associated_data_commitment
            .try_into()
            .map_err(|_| PrimitiveError::NotInField)?;
        Ok(self)
    }

    /// Set the associated data commitment from arbitrary bytes. This can be
    /// used to construct the associated data commitment in a canonical way.
    ///
    /// This method takes arbitrary bytes, converts them to field elements,
    /// applies a Poseidon2 hash, and stores the result as the associated data commitment.
    ///
    /// # Arguments
    /// * `data` - Arbitrary bytes to be committed (any length).
    ///
    /// # Errors
    /// Will error if the data is empty.
    pub fn associated_data_commitment_from_raw_bytes(
        mut self,
        data: &[u8],
    ) -> Result<Self, PrimitiveError> {
        self.associated_data_commitment =
            hash_bytes_to_field_element(ASSOCIATED_DATA_COMMITMENT_DS_TAG, data)?;
        Ok(self)
    }

    /// Get the credential domain separator for the given version.
    #[must_use]
    pub fn get_cred_ds(&self) -> FieldElement {
        match self.version {
            CredentialVersion::V1 => FieldElement::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ"),
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

    /// Computes the canonical hash of the Credential.
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
                    *self.associated_data_commitment,
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

    /// Compute the `sub` for a credential computed from `leaf_index` and a `blinding_factor`.
    #[must_use]
    pub fn compute_sub(leaf_index: u64, blinding_factor: FieldElement) -> FieldElement {
        let mut input = [
            *FieldElement::from_be_bytes_mod_order(SUB_DS_TAG),
            leaf_index.into(),
            *blinding_factor,
        ];
        poseidon2::bn254::t3::permutation_in_place(&mut input);
        input[1].into()
    }
}

impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializes the signature as compressed bytes (encoding r and s concatenated)
/// where `r` is compressed to a single coordinate. Result is hex-encoded.
#[expect(clippy::ref_option)]
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
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(sig))
    } else {
        serializer.serialize_bytes(&sig)
    }
}

fn deserialize_signature<'de, D>(deserializer: D) -> Result<Option<EdDSASignature>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Option<Vec<u8>> = if deserializer.is_human_readable() {
        Option::<String>::deserialize(deserializer)?
            .map(|s| hex::decode(s).map_err(de::Error::custom))
            .transpose()?
    } else {
        Option::<Vec<u8>>::deserialize(deserializer)?
    };

    let Some(bytes) = bytes else {
        return Ok(None);
    };

    if bytes.len() != 64 {
        return Err(de::Error::custom("Invalid signature. Expected 64 bytes."));
    }

    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    EdDSASignature::from_compressed_bytes(arr)
        .map(Some)
        .map_err(de::Error::custom)
}

fn serialize_public_key<S>(public_key: &EdDSAPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let pk = public_key
        .to_compressed_bytes()
        .map_err(serde::ser::Error::custom)?;
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(pk))
    } else {
        serializer.serialize_bytes(&pk)
    }
}

fn deserialize_public_key<'de, D>(deserializer: D) -> Result<EdDSAPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = if deserializer.is_human_readable() {
        hex::decode(String::deserialize(deserializer)?).map_err(de::Error::custom)?
    } else {
        Vec::<u8>::deserialize(deserializer)?
    };

    if bytes.len() != 32 {
        return Err(de::Error::custom("Invalid public key. Expected 32 bytes."));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    EdDSAPublicKey::from_compressed_bytes(arr).map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_associated_data_matches_direct_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Using the associated_data_commitment_from_raw_bytes method
        let credential = Credential::new()
            .associated_data_commitment_from_raw_bytes(&data)
            .unwrap();

        // Using the hash function directly
        let direct_hash =
            hash_bytes_to_field_element(ASSOCIATED_DATA_COMMITMENT_DS_TAG, &data).unwrap();

        // Both should produce the same hash
        assert_eq!(credential.associated_data_commitment, direct_hash);
    }

    #[test]
    fn test_associated_data_method() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        let credential = Credential::new()
            .associated_data_commitment_from_raw_bytes(&data)
            .unwrap();

        // Should have a non-zero associated data commitment
        assert_ne!(credential.associated_data_commitment, FieldElement::ZERO);
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
