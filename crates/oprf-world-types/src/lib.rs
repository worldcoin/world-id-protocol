use std::{fmt, str::FromStr};

use alloy::primitives::U256;
use ark_ff::PrimeField;
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
