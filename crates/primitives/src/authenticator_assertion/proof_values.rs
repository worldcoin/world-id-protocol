//! What a proof request and a proof response carry about an AAT.

use crate::{FieldElement, PrimitiveError};
use serde::{Deserialize, Serialize};

/// What an RP requires of the Authenticator Assertion Token (AAT) behind a Proof of Embedding
/// Similarity (WIP-202 §4.4).
///
/// The values are hints for the Authenticator. The RP checks the AAT values the proof reveals
/// against its own policy (WIP-202 §4.8).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AatRequirements {
    /// Whether the proof must come with a verified AAT.
    #[serde(default)]
    pub required: bool,
    /// The `platform` hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<u8>,
    /// The `sec_level` hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sec_level: Option<u8>,
    /// The `sec_meta` hint, 4 bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sec_meta: Option<u8>,
    /// The `authenticator_meta` hint, 5 bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_meta: Option<u8>,
}

impl AatRequirements {
    /// The width of `sec_meta` in bits.
    const SEC_META_BITS: u32 = 4;
    /// The width of `authenticator_meta` in bits.
    const AUTHENTICATOR_META_BITS: u32 = 5;

    /// Checks that every hint fits its width.
    ///
    /// # Errors
    /// Returns [`PrimitiveError::InvalidInput`] if `sec_meta` or `authenticator_meta` exceeds its
    /// width.
    pub fn validate(&self) -> Result<(), PrimitiveError> {
        let widths = [
            ("aat.sec_meta", self.sec_meta, Self::SEC_META_BITS),
            (
                "aat.authenticator_meta",
                self.authenticator_meta,
                Self::AUTHENTICATOR_META_BITS,
            ),
        ];
        for (attribute, value, bits) in widths {
            if value.is_some_and(|v| u32::from(v) >> bits != 0) {
                return Err(PrimitiveError::InvalidInput {
                    attribute: attribute.to_string(),
                    reason: format!("must fit in {bits} bits"),
                });
            }
        }
        Ok(())
    }
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
