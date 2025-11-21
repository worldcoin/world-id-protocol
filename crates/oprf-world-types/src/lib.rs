use std::{fmt, str::FromStr};

use alloy::primitives::U256;
use ark_ff::PrimeField;
use ark_serde_compat::babyjubjub;
use serde::{Deserialize, Serialize};

pub mod api;
pub mod proof_inputs;

/// Represents a merkle root hash. The inner type is a base field element from BabyJubJub for convenience instead of a scalar field element on BN254.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MerkleRoot(
    #[serde(
        serialize_with = "babyjubjub::serialize_fq",
        deserialize_with = "babyjubjub::deserialize_fq"
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
