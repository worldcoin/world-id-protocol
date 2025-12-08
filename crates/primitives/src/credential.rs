use ark_babyjubjub::{EdwardsAffine, Fq};
use ark_ff::{AdditiveGroup, Field};
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS};
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
    /// The subject (World ID) to which the credential is issued.
    ///
    /// This ID comes from the `AccountRegistry` and it's the `leaf_index` of the World ID on the Merkle tree.
    pub sub: u64,
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
            sub: 0,
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

    /// Set the `sub` of the credential.
    #[must_use]
    pub const fn sub(mut self, sub: u64) -> Self {
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
        self.associated_data_hash = Self::hash_bytes_to_field_element(data)?;
        Ok(self)
    }

    /// Hashes arbitrary bytes to a field element using Poseidon2 sponge construction.
    ///
    /// This uses a sponge construction to support **arbitrary length** input:
    /// 1. Split input into 31-byte chunks (each fits safely in a field element)
    /// 2. Absorb chunks in batches of up to 8 elements (rate) into the state
    /// 3. Apply Poseidon2 t16 permutation after each batch
    /// 4. Apply padding + domain separation (constant tag and length) and squeeze
    ///
    /// The state is divided into:
    /// - Rate portion (indices 0-7): where data is absorbed via addition
    /// - Capacity portion (indices 8-15): provides security, not directly modified by input
    ///
    /// # Arguments
    /// * `data` - Arbitrary bytes to hash (any length).
    ///
    /// # Errors
    /// Will error if the data is empty.
    pub fn hash_bytes_to_field_element(data: &[u8]) -> Result<FieldElement, PrimitiveError> {
        /// Number of bytes per chunk. 31 bytes = 248 bits, which fits safely in
        /// the BN254 scalar field (< 254 bits).
        const CHUNK_SIZE: usize = 31;
        /// Rate: number of field elements absorbed per permutation.
        /// Using 8 leaves 8 elements as capacity for security.
        const RATE: usize = 8;

        // Domain separation tag to avoid collisions with other Poseidon2 usages.
        const DS_TAG: &[u8] = b"ASSOCIATED_DATA_HASH_V1";

        if data.is_empty() {
            return Err(PrimitiveError::InvalidInput {
                attribute: "associated_data".to_string(),
                reason: "data cannot be empty".to_string(),
            });
        }

        let poseidon2: Poseidon2<Fq, 16, 5> = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);

        // Initialize state with zeros
        let mut state: [Fq; 16] = [Fq::ZERO; 16];

        // Apply domain separation in the capacity portion.
        state[RATE] += *FieldElement::from_be_bytes_mod_order(DS_TAG);

        // Convert bytes to field elements
        let field_elements: Vec<Fq> = data
            .chunks(CHUNK_SIZE)
            .map(|chunk| *FieldElement::from_be_bytes_mod_order(chunk))
            .collect();

        // Absorb field elements in batches of RATE
        for batch in field_elements.chunks(RATE) {
            // Add batch elements to the rate portion of the state
            for (i, &elem) in batch.iter().enumerate() {
                state[i] += elem;
            }
            // Apply permutation after each batch
            poseidon2.permutation_in_place(&mut state);
        }

        // Padding marks the end of data absorption; prefix-freedom is ensured by the combination
        // of this padding and the length encoding below, which prevents collisions between inputs
        // where one is a prefix of another.
        state[0] += Fq::ONE;
        poseidon2.permutation_in_place(&mut state);

        // Domain separation with length to avoid collisions between equal-prefix inputs of different lengths.
        // Use u128 to avoid truncation on very large inputs before reduction into the field.
        state[1] += Fq::from(data.len() as u128);
        poseidon2.permutation_in_place(&mut state);

        // Squeeze: return the second element (index 1) following the convention
        // used elsewhere in the codebase (claims_hash, credential hash)
        Ok(FieldElement::from(state[1]))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_to_field_element_basic() {
        let data = vec![1u8, 2, 3, 4, 5];
        let result = Credential::hash_bytes_to_field_element(&data);
        assert!(result.is_ok());

        // Should produce a non-zero result
        let hash = result.unwrap();
        assert_ne!(hash, FieldElement::ZERO);
    }

    #[test]
    fn test_hash_bytes_to_field_element_deterministic() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let hashed_value = "0x239c53416f3f05b279aca413f05b441ded343f98911c6289a83dcf4766bef5e0";
        let expected: FieldElement = hashed_value
            .parse()
            .expect("Failed to parse expected hash value");

        let result1 = Credential::hash_bytes_to_field_element(&data).unwrap();
        let result2 = Credential::hash_bytes_to_field_element(&data).unwrap();

        // Same input should produce same output
        assert_eq!(result1, result2);
        // Output should match expected value
        assert_eq!(result1, expected);
    }

    #[test]
    fn test_hash_bytes_to_field_element_different_inputs() {
        let data1 = vec![1u8, 2, 3, 4, 5];
        let data2 = vec![5u8, 4, 3, 2, 1];
        let data3 = vec![1u8, 2, 3, 4, 5, 6];

        let hash1 = Credential::hash_bytes_to_field_element(&data1).unwrap();
        let hash2 = Credential::hash_bytes_to_field_element(&data2).unwrap();
        let hash3 = Credential::hash_bytes_to_field_element(&data3).unwrap();

        // Different inputs should produce different outputs
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_hash_bytes_to_field_element_empty_error() {
        let data: Vec<u8> = vec![];
        let result = Credential::hash_bytes_to_field_element(&data);

        assert!(result.is_err());
        if let Err(PrimitiveError::InvalidInput { attribute, reason }) = result {
            assert_eq!(attribute, "associated_data");
            assert!(reason.contains("empty"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_hash_bytes_to_field_element_large_input() {
        // Test with a large input (10KB) to ensure arbitrary-length support
        let data = vec![42u8; 10 * 1024];
        let result = Credential::hash_bytes_to_field_element(&data);
        assert!(result.is_ok());

        // Should produce a non-zero result
        let hash = result.unwrap();
        assert_ne!(hash, FieldElement::ZERO);
    }

    #[test]
    fn test_hash_bytes_to_field_element_length_domain_separation() {
        // Two inputs with same data but different lengths should hash differently
        let data1 = vec![0u8; 10];
        let data2 = vec![0u8; 11];

        let hash1 = Credential::hash_bytes_to_field_element(&data1).unwrap();
        let hash2 = Credential::hash_bytes_to_field_element(&data2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_associated_data_method() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        let credential = Credential::new().associated_data(&data).unwrap();

        // Should have a non-zero associated data hash
        assert_ne!(credential.associated_data_hash, FieldElement::ZERO);
    }

    #[test]
    fn test_associated_data_vs_manual_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Using the associated_data method
        let credential = Credential::new().associated_data(&data).unwrap();

        // Using the hash function directly
        let direct_hash = Credential::hash_bytes_to_field_element(&data).unwrap();

        // Both should produce the same hash
        assert_eq!(credential.associated_data_hash, direct_hash);
    }
}
