#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
pub use oprf_zk::groth16_serde::Groth16Proof;

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// The `A` element in `G1`.
    #[serde(rename = "pi_a")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1")]
    pub a: ark_bn254::G1Affine,
    /// The `B` element in `G2`.
    #[serde(rename = "pi_b")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g2")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g2")]
    pub b: ark_bn254::G2Affine,
    /// The `C` element in `G1`.
    #[serde(rename = "pi_c")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1")]
    pub c: ark_bn254::G1Affine,
}
