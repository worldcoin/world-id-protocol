#![doc = include_str!("../README.md")]

use ark_babyjubjub::Fq;
use ark_ff::PrimeField as _;
use world_id_primitives::{DomainSeparator, FieldElement, poseidon};

mod token;
pub use token::{
    AatClaims, COSE_ALG_FLAMINGO_TOKEN, EAT_PROFILE, FlamingoClaims, FlamingoToken, MAX_COMPARED,
    TokenError,
};

/// Separates the signed digest of a Flamingo Token. The digest runs at `t=16`, so the
/// separator pins 15 inputs.
pub const DS_SIGN: DomainSeparator<15> = DomainSeparator::new(b"WORLD-ID/WIP-201/SIGN");
/// Separates [`engine_config_hash`].
pub const DS_ENGINE: DomainSeparator<3> = DomainSeparator::new(b"WORLD-ID/WIP-201/ENGINE");

/// `R(d)`: a 256-bit digest read as a big-endian integer modulo p.
#[must_use]
pub fn digest_to_field(digest: &[u8; 32]) -> FieldElement {
    Fq::from_be_bytes_mod_order(digest).into()
}

/// `engine_config_hash = H_4(DS_ENGINE; R(engine_hash), pipeline, match_strictness)`, the
/// value RPs allowlist.
#[must_use]
pub fn engine_config_hash(
    engine_hash: &[u8; 32],
    pipeline: u32,
    match_strictness: u8,
) -> FieldElement {
    poseidon::hash(
        DS_ENGINE,
        [
            digest_to_field(engine_hash),
            u64::from(pipeline).into(),
            u64::from(match_strictness).into(),
        ],
    )
}
