//! What a proof request and a proof response carry about an AAT.

use crate::FieldElement;
use serde::{Deserialize, Serialize};

/// What an RP requires of the Authenticator Assertion Token (AAT) behind a Proof of Embedding
/// Similarity (WIP-202 §4.4).
///
/// The RP checks the AAT values the proof reveals against its own policy (WIP-202 §4.8).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AatRequirements {
    /// Whether the proof must come with a verified AAT.
    #[serde(default)]
    pub required: bool,
}

/// The public values of the Authenticator Assertion Token (AAT) a proof reveals.
///
/// Absent from a response when the Flamingo Verifier verified no AAT (`has_aat = 0`), in which
/// case all of them are zero in the circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AatPublicValues {
    /// The WIP-106 hash of the trust anchor key that signed the verified Trust Anchor Key Token.
    pub trust_anchor_key_hash: FieldElement,
    /// The platform.
    pub platform: u8,
    /// The security level.
    pub sec_level: u8,
    /// The security metadata, 4 bits.
    pub sec_meta: u8,
    /// The Authenticator metadata, 5 bits.
    pub authenticator_meta: u8,
}

impl AatPublicValues {
    /// The width of `sec_meta` in bits.
    pub const SEC_META_BITS: u32 = 4;
    /// The width of `authenticator_meta` in bits.
    pub const AUTHENTICATOR_META_BITS: u32 = 5;
}
