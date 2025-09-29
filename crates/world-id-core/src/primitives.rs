//! Introduces low level primitives for interacting with the World ID Protocol.

use ark_babyjubjub::Fq;
use ark_bn254::Fr;
pub use ark_ff::AdditiveGroup;
use ark_ff::{BigInteger, PrimeField};
use ruint::aliases::U256;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

/// The base field used for point coordinates in the World ID Protocol.
///
/// This is the field of the BN254 curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BaseField(pub Fq);

impl BaseField {
    /// The zero element of the base field.
    pub const ZERO: Self = Self(Fq::ZERO);
}

/// The scalar field used for multipliers for EC operations in the World ID Protocol.
///
/// This is the field of the BN254 curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarField(pub Fr);

impl Serialize for BaseField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.0.into_bigint();

        if serializer.is_human_readable() {
            let uint = U256::from_limbs(value.0);
            serializer.serialize_str(&format!("{uint:#066x}"))
        } else {
            value.to_bytes_be().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for BaseField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = if deserializer.is_human_readable() {
            let mut s: String = Deserialize::deserialize(deserializer)?;
            if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                s = rest.to_string();
            }

            hex::decode(&s).map_err(D::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };
        // TODO: Check the expected length?
        Ok(Self(Fq::from_be_bytes_mod_order(&bytes)))
    }
}

impl From<u64> for BaseField {
    fn from(value: u64) -> Self {
        Self(Fq::from(value))
    }
}
