use crate::{
    FieldElement, PrimitiveError, authenticator::AuthenticatorPublicKeySet, serde_utils::hex_u64,
};
use ark_bn254::Fr;
use poseidon2::Poseidon2;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

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
/// This is generally used to prove inclusion into the set of World ID Accounts (`WorldIDRegistry`);
/// each authenticator public key is tied to a leaf in a Merkle tree, where each leaf represents
/// a unique World ID Account.
///
/// To prove validity, the user shows membership in the tree with a sibling path up to the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInclusionProof<const TREE_DEPTH: usize> {
    /// The root hash of the Merkle tree.
    pub root: FieldElement,
    /// The World ID's leaf position in the Merkle tree of the `WorldIDRegistry` contract.
    ///
    /// This is the main internal identifier for a World ID.
    #[serde(with = "hex_u64")]
    pub leaf_index: u64,
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
        siblings: [FieldElement; TREE_DEPTH],
    ) -> Self {
        Self {
            root,
            leaf_index,
            siblings,
        }
    }

    /// Validates the Merkle inclusion proof structure for a given leaf.
    pub fn is_valid(&self, leaf: FieldElement) -> bool {
        let poseidon2_2: Poseidon2<Fr, 2, 5> = Poseidon2::default();
        let mut computed = leaf.0;
        for (idx, sibling) in self.siblings.iter().enumerate() {
            if (self.leaf_index >> idx) & 1 == 0 {
                computed = poseidon2_compress(&poseidon2_2, computed, sibling.0);
            } else {
                computed = poseidon2_compress(&poseidon2_2, sibling.0, computed);
            }
        }
        computed == self.root.0
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
    pub inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The compressed authenticator public keys for the account (as `U256` values).
    ///
    /// Each public key is serialized in compressed form for efficient storage and transmission.
    pub authenticator_pubkeys: AuthenticatorPublicKeySet,
}

impl<const TREE_DEPTH: usize> AccountInclusionProof<TREE_DEPTH> {
    /// Creates a new account inclusion proof.
    ///
    /// # Errors
    /// Returns an error if the number of authenticator public keys exceeds `MAX_AUTHENTICATOR_KEYS`.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(
        inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
        authenticator_pubkeys: AuthenticatorPublicKeySet,
    ) -> Result<Self, PrimitiveError> {
        Ok(Self {
            inclusion_proof,
            authenticator_pubkeys,
        })
    }
}

/// Poseidon2 "compress" for a pair of field elements (left, right).
fn poseidon2_compress(poseidon2: &Poseidon2<Fr, 2, 5>, left: Fr, right: Fr) -> Fr {
    let mut state = poseidon2.permutation(&[left, right]);
    state[0] += left;
    state[0]
}
