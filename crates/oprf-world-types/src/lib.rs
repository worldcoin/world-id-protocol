use std::{fmt, str::FromStr};

use alloy::primitives::U256;
use ark_ff::PrimeField;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use serde::{Deserialize, Serialize};

pub mod api;
pub mod proof_inputs;

/// The depth of the merkle-tree
pub const TREE_DEPTH: usize = 30;

/// Represents a merkle root hash. The inner type is a base field element from BabyJubJub for convenience instead of a scalar field element on BN254.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MerkleRoot(
    #[serde(
        serialize_with = "ark_serde_compat::serialize_babyjubjub_fq",
        deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fq"
    )]
    ark_babyjubjub::Fq,
);

impl MerkleRoot {
    /// Creates a new `MerkleRoot` by wrapping a base field element of BabyJubJub (which is equivalent to BN254 scalar field)
    pub fn new(f: ark_babyjubjub::Fq) -> Self {
        Self::from(f)
    }
    /// Converts the merkle-root hash to its inner value, which is an element in the base field of BabyJubJub (which is equivalent to BN254 scalar field)
    pub fn into_inner(self) -> ark_babyjubjub::Fq {
        self.0
    }
}

impl FromStr for MerkleRoot {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(ark_babyjubjub::Fq::from_str(s)?))
    }
}

impl From<U256> for MerkleRoot {
    fn from(value: U256) -> Self {
        Self(ark_babyjubjub::Fq::new(ark_ff::BigInt(value.into_limbs())))
    }
}

impl From<MerkleRoot> for U256 {
    fn from(value: MerkleRoot) -> Self {
        U256::from_limbs(value.0.into_bigint().0)
    }
}

impl From<ark_babyjubjub::Fq> for MerkleRoot {
    fn from(value: ark_babyjubjub::Fq) -> Self {
        Self(value)
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

/// A batch of end-user public keys
///
/// Stored in the Merkle-Tree at the Smart Contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublicKeyBatch {
    /// Values of the the public key (always len 7)
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine_sequence")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_user_key_batch")]
    pub values: [ark_babyjubjub::EdwardsAffine; 7],
}

impl UserPublicKeyBatch {
    /// Convert to inner `[ark_babyjubjub::EdwardsAffine; 7]`.
    pub fn into_inner(self) -> [ark_babyjubjub::EdwardsAffine; 7] {
        self.values
    }
}

/// Key material for the end-user.
///
/// Each user manages a batch of public keys but only one active
/// secret key. The `pk_index` selects which key in the batch
/// corresponds to the private key.
///
/// **Note**: Callers must ensure `pk_index < 7`.  
/// This implementation will panic if the index is out of bounds.
#[derive(Clone)]
pub struct UserKeyMaterial {
    /// A batch of public keys.
    pub pk_batch: UserPublicKeyBatch,
    /// The index in the batch that corresponds to the user’s public key.
    pub pk_index: u64, // 0..6
    /// The user’s private key.
    pub sk: EdDSAPrivateKey,
}

impl UserKeyMaterial {
    /// Returns the user’s currently active public key.
    ///
    /// # Panics
    ///
    /// Panics if `pk_index` is out of bounds relative to [`oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS`].
    pub fn public_key(&self) -> ark_babyjubjub::EdwardsAffine {
        self.pk_batch.values[self.pk_index as usize]
    }
}

/// A credential object in the world ecosystem, together with its signature.  
/// See [Notion doc](https://www.notion.so/worldcoin/WID25-Credential-PCP-Structure-Lifecycle-2668614bdf8c805d9484d7dd8f68532b?source=copy_link#2698614bdf8c808f83ebe8889dad0af6) for details.
///
/// The user must prove in a ZK proof that they hold a valid credential
/// and that it was signed by an authorized issuer.
#[derive(Clone)]
pub struct CredentialsSignature {
    /// Unique credential type ID. Not relevant for the OPRF service,
    /// but included in the signature.
    pub type_id: ark_babyjubjub::Fq,
    /// The `claims hash` + `associated data hash`.
    pub hashes: [ark_babyjubjub::Fq; 2], // [claims_hash, associated_data_hash]
    /// Timestamp of original issuance (unix secs).
    pub genesis_issued_at: u64,
    /// Expiration timestamp (unix secs).
    pub expires_at: u64,
    /// The issuer of the credential.  
    /// Currently this is a public input to the Groth16 proof.  
    /// In upcoming versions, the OPRF service will fetch the issuer’s
    /// public key from chain (or another trusted source).
    pub issuer: EdDSAPublicKey,
    /// The credential’s signature object.
    pub signature: EdDSASignature,
}

/// Artifacts required to compute the Merkle inclusion proof
/// for a user’s public key.
///
/// Each public key is tied to a leaf in a Merkle tree.
/// To prove validity, the user shows membership in the tree
/// with a sibling path up to the root.
#[derive(Clone)]
pub struct MerkleMembership {
    /// The actual Merkle root (not sent to the OPRF service, only used for computing the proof).
    pub root: MerkleRoot,
    /// The index of the user’s leaf in the Merkle tree.
    pub mt_index: u64,
    /// The sibling path up to the Merkle root.  
    pub siblings: [ark_babyjubjub::Fq; TREE_DEPTH],
}
