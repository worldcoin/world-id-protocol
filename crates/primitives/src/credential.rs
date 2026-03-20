use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{FieldElement, PrimitiveError};

#[cfg(feature = "crypto")]
use {
    crate::sponge::hash_bytes_to_field_element,
    ark_babyjubjub::EdwardsAffine,
    eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature},
    rand::Rng,
};

#[cfg(feature = "crypto")]
mod ds_tags {
    pub const ASSOCIATED_DATA_HASH: &[u8] = b"ASSOCIATED_DATA_HASH_V1";
    pub const CLAIMS_HASH: &[u8] = b"CLAIMS_HASH_V1";
    pub const SUB: &[u8] = b"H_CS(id, r)";
}

fn serialize_fixed_bytes<S, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

fn deserialize_fixed_bytes<'de, D, const N: usize>(
    deserializer: D,
    type_name: &str,
) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = if deserializer.is_human_readable() {
        hex::decode(String::deserialize(deserializer)?).map_err(de::Error::custom)?
    } else {
        Vec::<u8>::deserialize(deserializer)?
    };

    bytes
        .try_into()
        .map_err(|_| de::Error::custom(format!("Invalid {type_name}. Expected {N} bytes.")))
}

#[cfg(feature = "crypto")]
fn deserialize_optional_fixed_bytes<'de, D, const N: usize>(
    deserializer: D,
    type_name: &str,
) -> Result<Option<[u8; N]>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = if deserializer.is_human_readable() {
        Option::<String>::deserialize(deserializer)?
            .map(|value| hex::decode(value).map_err(de::Error::custom))
            .transpose()?
    } else {
        Option::<Vec<u8>>::deserialize(deserializer)?
    };

    bytes
        .map(|value| {
            value
                .try_into()
                .map_err(|_| de::Error::custom(format!("Invalid {type_name}. Expected {N} bytes.")))
        })
        .transpose()
}

/// Version of the `Credential` object.
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

/// Opaque EdDSA public key (32 compressed bytes).
///
/// Serde-compatible with `EdDSAPublicKey` from the `eddsa-babyjubjub` crate.
#[cfg(not(feature = "crypto"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PublicKeyBytes([u8; 32]);

#[cfg(not(feature = "crypto"))]
impl PublicKeyBytes {
    /// Creates an opaque public key from compressed bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the compressed public key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the compressed public key bytes by value.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[cfg(not(feature = "crypto"))]
impl From<[u8; 32]> for PublicKeyBytes {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

#[cfg(not(feature = "crypto"))]
impl Serialize for PublicKeyBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed_bytes(&self.0, serializer)
    }
}

#[cfg(not(feature = "crypto"))]
impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_fixed_bytes(deserializer, "public key").map(Self)
    }
}

/// Opaque EdDSA signature (64 compressed bytes).
///
/// Serde-compatible with `EdDSASignature` from the `eddsa-babyjubjub` crate.
#[cfg(not(feature = "crypto"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureBytes([u8; 64]);

#[cfg(not(feature = "crypto"))]
impl SignatureBytes {
    /// Creates an opaque signature from compressed bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the compressed signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Returns the compressed signature bytes by value.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

#[cfg(not(feature = "crypto"))]
impl From<[u8; 64]> for SignatureBytes {
    fn from(bytes: [u8; 64]) -> Self {
        Self::new(bytes)
    }
}

#[cfg(not(feature = "crypto"))]
impl Default for SignatureBytes {
    fn default() -> Self {
        Self([0; 64])
    }
}

#[cfg(not(feature = "crypto"))]
impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed_bytes(&self.0, serializer)
    }
}

#[cfg(not(feature = "crypto"))]
impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_fixed_bytes(deserializer, "signature").map(Self)
    }
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
    #[cfg(feature = "crypto")]
    #[serde(serialize_with = "serialize_signature")]
    #[serde(deserialize_with = "deserialize_signature")]
    #[serde(default)]
    pub signature: Option<EdDSASignature>,
    /// The signature of the credential (signed by the issuer's key)
    #[cfg(not(feature = "crypto"))]
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
    /// The public component of the issuer's key which signed the Credential.
    #[cfg(feature = "crypto")]
    #[serde(serialize_with = "serialize_public_key")]
    #[serde(deserialize_with = "deserialize_public_key")]
    pub issuer: EdDSAPublicKey,
    /// The public component of the issuer's key which signed the Credential.
    #[cfg(not(feature = "crypto"))]
    pub issuer: PublicKeyBytes,
}

impl Credential {
    /// The maximum number of claims that can be included in a credential.
    pub const MAX_CLAIMS: usize = 16;

    /// Initializes a new credential.
    ///
    /// Default field elements use the zero sentinel.
    #[cfg(feature = "crypto")]
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
    #[cfg(feature = "crypto")]
    pub fn claim(mut self, index: usize, claim: &[u8]) -> Result<Self, PrimitiveError> {
        if index >= self.claims.len() {
            return Err(PrimitiveError::OutOfBounds);
        }
        self.claims[index] = hash_bytes_to_field_element(ds_tags::CLAIMS_HASH, claim)?;
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
    #[cfg(feature = "crypto")]
    pub fn associated_data(mut self, data: &[u8]) -> Result<Self, PrimitiveError> {
        self.associated_data_hash =
            hash_bytes_to_field_element(ds_tags::ASSOCIATED_DATA_HASH, data)?;
        Ok(self)
    }

    /// Get the credential domain separator for the given version.
    #[cfg(feature = "crypto")]
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
    #[cfg(feature = "crypto")]
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

    /// Computes the specifically designed hash of the credential for the given version.
    ///
    /// The hash is signed by the issuer to provide authenticity for the credential.
    ///
    /// # Errors
    /// - Will error if there are more claims than the maximum allowed.
    /// - Will error if the claims cannot be lowered into the field. Should not occur in practice.
    #[cfg(feature = "crypto")]
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
    #[cfg(feature = "crypto")]
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
    #[cfg(feature = "crypto")]
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
    #[cfg(feature = "crypto")]
    #[must_use]
    pub fn compute_sub(leaf_index: u64, blinding_factor: FieldElement) -> FieldElement {
        let mut input = [
            *FieldElement::from_be_bytes_mod_order(ds_tags::SUB),
            leaf_index.into(),
            *blinding_factor,
        ];
        poseidon2::bn254::t3::permutation_in_place(&mut input);
        input[1].into()
    }
}

#[cfg(feature = "crypto")]
impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializes the signature as compressed bytes (encoding r and s concatenated)
/// where `r` is compressed to a single coordinate. Result is hex-encoded.
#[cfg(feature = "crypto")]
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
    serialize_fixed_bytes(&sig, serializer)
}

#[cfg(feature = "crypto")]
fn deserialize_signature<'de, D>(deserializer: D) -> Result<Option<EdDSASignature>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(bytes) = deserialize_optional_fixed_bytes(deserializer, "signature")? else {
        return Ok(None);
    };

    EdDSASignature::from_compressed_bytes(bytes)
        .map(Some)
        .map_err(de::Error::custom)
}

#[cfg(feature = "crypto")]
fn serialize_public_key<S>(public_key: &EdDSAPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let pk = public_key
        .to_compressed_bytes()
        .map_err(serde::ser::Error::custom)?;
    serialize_fixed_bytes(&pk, serializer)
}

#[cfg(feature = "crypto")]
fn deserialize_public_key<'de, D>(deserializer: D) -> Result<EdDSAPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_fixed_bytes(deserializer, "public key")?;
    EdDSAPublicKey::from_compressed_bytes(bytes).map_err(de::Error::custom)
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;

    #[test]
    fn test_associated_data_matches_direct_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let credential = Credential::new().associated_data(&data).unwrap();
        let direct_hash =
            hash_bytes_to_field_element(ds_tags::ASSOCIATED_DATA_HASH, &data).unwrap();

        assert_eq!(credential.associated_data_hash, direct_hash);
    }

    #[test]
    fn test_associated_data_method() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        let credential = Credential::new().associated_data(&data).unwrap();

        assert_ne!(credential.associated_data_hash, FieldElement::ZERO);
    }

    #[test]
    fn test_claim_matches_direct_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let credential = Credential::new().claim(0, &data).unwrap();
        let direct_hash = hash_bytes_to_field_element(ds_tags::CLAIMS_HASH, &data).unwrap();

        assert_eq!(credential.claims[0], direct_hash);
    }

    #[test]
    fn test_claim_method() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        let credential = Credential::new().claim(1, &data).unwrap();

        assert_ne!(credential.claims[1], FieldElement::ZERO);
    }
}

#[cfg(all(test, not(feature = "crypto")))]
mod non_crypto_tests {
    use super::*;

    #[test]
    fn test_credential_json_roundtrip() {
        let credential = Credential {
            id: 1,
            version: CredentialVersion::V1,
            issuer_schema_id: 2,
            sub: FieldElement::from(3u64),
            genesis_issued_at: 4,
            expires_at: 5,
            claims: vec![FieldElement::from(6u64), FieldElement::from(7u64)],
            associated_data_hash: FieldElement::from(8u64),
            signature: Some(SignatureBytes::new([0x22; 64])),
            issuer: PublicKeyBytes::new([0x11; 32]),
        };

        let json = serde_json::to_value(&credential).unwrap();
        assert_eq!(
            json["issuer"],
            serde_json::Value::String(hex::encode([0x11; 32]))
        );
        assert_eq!(
            json["signature"],
            serde_json::Value::String(hex::encode([0x22; 64]))
        );

        let roundtrip: Credential = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.issuer.as_bytes(), &[0x11; 32]);
        assert_eq!(roundtrip.signature.unwrap().as_bytes(), &[0x22; 64]);
        assert_eq!(roundtrip.claims, credential.claims);
        assert_eq!(roundtrip.sub, credential.sub);
    }

    #[test]
    fn test_credential_cbor_roundtrip() {
        let credential = Credential {
            id: 9,
            version: CredentialVersion::V1,
            issuer_schema_id: 10,
            sub: FieldElement::from(11u64),
            genesis_issued_at: 12,
            expires_at: 13,
            claims: vec![FieldElement::from(14u64)],
            associated_data_hash: FieldElement::from(15u64),
            signature: Some(SignatureBytes::new([0x44; 64])),
            issuer: PublicKeyBytes::new([0x33; 32]),
        };

        let mut buffer = Vec::new();
        ciborium::into_writer(&credential, &mut buffer).unwrap();

        let roundtrip: Credential = ciborium::from_reader(&buffer[..]).unwrap();
        assert_eq!(roundtrip.issuer.as_bytes(), &[0x33; 32]);
        assert_eq!(roundtrip.signature.unwrap().as_bytes(), &[0x44; 64]);
        assert_eq!(roundtrip.claims, credential.claims);
        assert_eq!(roundtrip.sub, credential.sub);
    }
}
