use std::{fmt, str::FromStr};

use ark_ff::PrimeField;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

pub mod proof;
pub use proof::WorldIdProof;

pub mod rp;

/// The base field (curve field `Fq`) over which the elliptic curve is defined for the curve that is used to
/// sign credentials in the World ID Protocol. The World ID Protocol currently uses the `BabyJubJub` curve.
pub type BaseField = ark_babyjubjub::Fq;

/// Represents a Merkle root hash for any of the trees in the World ID Protocol.
///
/// The inner type is a base field element from BabyJubJub for convenience instead of a scalar field element on BN254.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MerkleRoot(
    #[serde(
        serialize_with = "ark_serde_compat::serialize_babyjubjub_base",
        deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base"
    )]
    ark_babyjubjub::Fq,
);

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

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TypeError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
}
