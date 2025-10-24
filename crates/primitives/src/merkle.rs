use crate::{authenticator::MAX_AUTHENTICATOR_KEYS, FieldElement, TypeError};
use ruint::aliases::U256;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// Helper module for serializing/deserializing fixed-size arrays.
mod array_serde {
    use super::*;

    pub fn serialize<S, T, const N: usize>(array: &[T; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        array.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D, T, const N: usize>(deserializer: D) -> Result<[T; N], D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        let vec = Vec::<T>::deserialize(deserializer)?;
        vec.try_into().map_err(|v: Vec<_>| {
            D::Error::custom(format!("Expected array of size {}, got {}", N, v.len()))
        })
    }
}

/// Artifact required to compute the Merkle inclusion proof.
///
/// This is generally used to prove inclusion into the set of World ID Accounts (`AccountRegistry`);
/// each authenticator public key is tied to a leaf in a Merkle tree, where each leaf represents
/// a unique World ID Account.
///
/// To prove validity, the user shows membership in the tree with a sibling path up to the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInclusionProof<const TREE_DEPTH: usize> {
    /// The root hash of the Merkle tree.
    pub root: FieldElement,
    /// The logical index of the user's leaf in the Merkle tree.
    pub leaf_index: u64,
    /// The user's account ID which is represented by the leaf position in the Merkle tree.
    ///
    /// This is the `leaf_index` + 1 (because the `account_id` is initialized to `1`).
    pub account_id: u64,
    /// The sibling path up to the Merkle root.
    #[serde(with = "array_serde")]
    pub siblings: [FieldElement; TREE_DEPTH],
}

impl<const TREE_DEPTH: usize> MerkleInclusionProof<TREE_DEPTH> {
    /// Creates a new Merkle inclusion proof.
    #[must_use]
    pub const fn new(
        root: FieldElement,
        leaf_index: u64,
        account_id: u64,
        siblings: [FieldElement; TREE_DEPTH],
    ) -> Self {
        Self {
            root,
            leaf_index,
            account_id,
            siblings,
        }
    }
}

/// Response containing a Merkle inclusion proof along with the authenticator public keys
/// for a World ID Account.
///
/// This is typically returned by the indexer when requesting proof of account membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInclusionProof<const TREE_DEPTH: usize> {
    /// The Merkle inclusion proof.
    #[serde(flatten)]
    pub proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The compressed authenticator public keys for the account (as `U256` values).
    ///
    /// Each public key is serialized in compressed form for efficient storage and transmission.
    pub authenticator_pubkeys: Vec<U256>,
}

impl<const TREE_DEPTH: usize> AccountInclusionProof<TREE_DEPTH> {
    /// Creates a new account inclusion proof.
    ///
    /// # Errors
    /// Returns an error if the number of authenticator public keys exceeds [`MAX_AUTHENTICATOR_KEYS`].
    pub fn new(
        proof: MerkleInclusionProof<TREE_DEPTH>,
        authenticator_pubkeys: Vec<U256>,
    ) -> Result<Self, TypeError> {
        if authenticator_pubkeys.len() > MAX_AUTHENTICATOR_KEYS {
            return Err(TypeError::OutOfBounds);
        }
        Ok(Self {
            proof,
            authenticator_pubkeys,
        })
    }

    /// Creates a new account inclusion proof without validation.
    ///
    /// # Safety
    /// The caller must ensure that the number of authenticator public keys does not exceed [`MAX_AUTHENTICATOR_KEYS`].
    #[must_use]
    pub const fn new_unchecked(
        proof: MerkleInclusionProof<TREE_DEPTH>,
        authenticator_pubkeys: Vec<U256>,
    ) -> Self {
        Self {
            proof,
            authenticator_pubkeys,
        }
    }
}
