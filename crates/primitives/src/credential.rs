use ark_babyjubjub::EdwardsAffine;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use ruint::aliases::U256;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{FieldElement, PrimitiveError};

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
/// Design Principles:
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
    /// Version representation of this structure
    pub version: CredentialVersion,
    /// Unique credential type id that is used to lookup of verifying information
    pub issuer_schema_id: u64,
    /// World ID to which the credential is issued. This ID comes from the `AccountRegistry`.
    ///
    /// This is the primary internal identifier of a World ID.
    pub leaf_index: u64,
    /// Timestamp of **first issuance** of this credential (unix seconds), i.e. this represents when the holder
    /// first obtained the credential. Even if the credential has been issued multiple times (e.g. because of a renewal),
    /// this timestamp should stay constant.
    pub genesis_issued_at: u64,
    /// Expiration timestamp (unix seconds)
    pub expires_at: u64,
    /// These are concrete statements that the issuer attests about the receiver.
    /// Could be just commitments to data (e.g. passport image) or
    /// the value directly (e.g. date of birth)
    pub claims: Vec<FieldElement>,
    /// If needed, can be used as commitment to the underlying data.
    /// This can be useful to tie multiple proofs about the same data together.
    pub associated_data_hash: FieldElement,
    /// The signature of the credential (signed by the issuer's key)
    #[serde(serialize_with = "serialize_signature")]
    #[serde(deserialize_with = "deserialize_signature")]
    #[serde(default)]
    pub signature: Option<EdDSASignature>,
    /// The issuer's public key of the credential.
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
        Self {
            version: CredentialVersion::V1,
            issuer_schema_id: 0,
            leaf_index: 0,
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

    /// Set the `leafIndex` of the credential.
    #[must_use]
    pub const fn leaf_index(mut self, leaf_index: u64) -> Self {
        self.leaf_index = leaf_index;
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
    pub fn claim(mut self, index: usize, claim: U256) -> Result<Self, PrimitiveError> {
        if index >= self.claims.len() {
            return Err(PrimitiveError::OutOfBounds);
        }
        self.claims[index] = claim.try_into().map_err(|_| PrimitiveError::NotInField)?;
        Ok(self)
    }

    /// Set the associated data hash of the credential.
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

    /// Get the credential domain separator for the given version.
    #[must_use]
    pub fn get_cred_ds(&self) -> FieldElement {
        match self.version {
            CredentialVersion::V1 => {
                FieldElement::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ+DLBE-v1")
            }
        }
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
