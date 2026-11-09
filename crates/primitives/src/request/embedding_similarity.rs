//! Request and response types of the WIP-202 Proof of Embedding Similarity.
//!
//! WIP-202 leaves the encoding of the proof request and response outside the WIP; this module is
//! that encoding on top of the existing request format.

use crate::{
    EmbeddingSimilarityProof, FieldElement, OprfPrefix, OprfPrefixedFieldElement as _,
    PrimitiveError, authenticator_assertion::AatRequirements,
};
use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};

/// The parameters only a Proof of Embedding Similarity request takes (WIP-202 §4.4).
///
/// The Credential policy and the `signal` are the request's single [`RequestItem`], and the
/// request's `session_id` is the optional session.
///
/// [`RequestItem`]: super::RequestItem
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingSimilarityParams {
    /// An RP-chosen action whose most significant byte is [`OprfPrefix::EmbeddingSimilarity`].
    ///
    /// The proof does not use it. The RP's signature over it authorizes the registration of the
    /// user's World ID under WIP-107 (§4.5).
    pub action: FieldElement,
    /// `R(SHA-256(challenge))` of the challenge image, which the RP computes itself. It is never
    /// zero, since zero marks an unused position of the Flamingo Token.
    pub challenge_hash: FieldElement,
    /// The AAT requirements, if the RP states any.
    pub aat: Option<AatRequirements>,
}

impl EmbeddingSimilarityParams {
    /// Checks what the type does not enforce itself.
    ///
    /// # Errors
    /// Returns [`PrimitiveError::InvalidInput`] if the `action` does not carry
    /// [`OprfPrefix::EmbeddingSimilarity`], the `challenge_hash` is zero, or an AAT hint exceeds
    /// its width.
    pub fn validate(&self) -> Result<(), PrimitiveError> {
        if !self.action.has_prefix(OprfPrefix::EmbeddingSimilarity) {
            return Err(PrimitiveError::InvalidInput {
                attribute: "action".to_string(),
                reason: format!(
                    "MSB must be 0x{:02x}",
                    OprfPrefix::EmbeddingSimilarity as u8
                ),
            });
        }
        if self.challenge_hash == FieldElement::ZERO {
            return Err(PrimitiveError::InvalidInput {
                attribute: "challenge_hash".to_string(),
                reason: "must not be zero".to_string(),
            });
        }
        self.aat.as_ref().map_or(Ok(()), AatRequirements::validate)
    }
}

/// The result of a Proof of Embedding Similarity (WIP-202), carried in
/// [`ProofResponse::embedding_similarity`](super::ProofResponse::embedding_similarity).
///
/// Unknown JSON fields are ignored during deserialization; see [`super::ProofResponse`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingSimilarityResponseItem {
    /// The `identifier` of the request's single [`RequestItem`](super::RequestItem).
    pub identifier: String,
    /// The proof and the public inputs the prover chose. Nested rather than flattened: ProveKit
    /// encodes the proof by whether the format is human-readable, which flattening hides.
    pub proof: EmbeddingSimilarityProof,
    /// The Flamingo Verifier's attestation of `flamingo_verifier_key` (WIP-201 §4.7).
    pub signing_key_attestation: Bytes,
}
