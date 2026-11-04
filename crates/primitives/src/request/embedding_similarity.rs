//! Request and response types of the WIP-202 Proof of Embedding Similarity.
//!
//! WIP-202 leaves the encoding of the proof request and response outside the WIP; this module is
//! that encoding on top of the existing request format.

use crate::{
    EdDSAPublicKey, FieldElement, OprfPrefix, OprfPrefixedFieldElement as _, PrimitiveError,
    authenticator_assertion::{AatPublicValues, AatRequirements},
    credential::{deserialize_public_key, serialize_public_key},
};
use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};

/// The most Flamingo configurations a request may offer, which bounds the work of validating it.
pub const MAX_FLAMINGO_CONFIGURATIONS: usize = 16;

/// A Flamingo configuration the RP accepts (WIP-202 §4.4).
///
/// The Authenticator picks one the Flamingo Verifier it uses offers. The RP checks that the
/// proof's `engine_config_hash` is the hash of a configuration it accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamingoConfiguration {
    /// The Engine Provider whose release manifest defines the pipeline.
    pub iss: String,
    /// The pipeline, whose first input MUST have role `live_frame`.
    pub pipeline_id: u16,
    /// The match strictness level of the pipeline.
    pub match_strictness: u8,
    /// The lowest release `version` of the Engine Provider the RP accepts.
    pub min_version: u64,
}

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
    /// The Flamingo configurations the RP accepts, from one to [`MAX_FLAMINGO_CONFIGURATIONS`].
    pub flamingo_configurations: Vec<FlamingoConfiguration>,
    /// The AAT requirements, if the RP states any.
    pub aat: Option<AatRequirements>,
}

impl EmbeddingSimilarityParams {
    /// Checks what the type does not enforce itself.
    ///
    /// # Errors
    /// Returns [`PrimitiveError::InvalidInput`] if the `action` does not carry
    /// [`OprfPrefix::EmbeddingSimilarity`], the `challenge_hash` is zero, the number of Flamingo
    /// configurations is out of range, or an AAT hint exceeds its width.
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
        let configurations = self.flamingo_configurations.len();
        if !(1..=MAX_FLAMINGO_CONFIGURATIONS).contains(&configurations) {
            return Err(PrimitiveError::InvalidInput {
                attribute: "flamingo_configurations".to_string(),
                reason: format!("must have 1 to {MAX_FLAMINGO_CONFIGURATIONS} entries"),
            });
        }
        self.aat.as_ref().map_or(Ok(()), AatRequirements::validate)
    }
}

/// The result of a Proof of Embedding Similarity (WIP-202), carried in
/// [`ProofResponse::embedding_similarity`](super::ProofResponse::embedding_similarity).
///
/// It carries the public inputs of the circuit that the request does not fix. The RP verifies the
/// proof with its own copies of the others: `rp_id`, `nonce`, `challenge_hash`, `signal_hash`,
/// the Credential policy and the session (WIP-202 §4.8).
///
/// Unknown JSON fields are ignored during deserialization; see [`super::ProofResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingSimilarityResponseItem {
    /// The `identifier` of the [`RequestItem`](super::RequestItem) of the PoH Credential.
    pub identifier: String,
    /// The `issuer_schema_id` of the Credential.
    pub issuer_schema_id: u64,
    /// The encoded proof (WIP-202 §4.7).
    pub proof: Bytes,
    /// The Flamingo Verifier's signing key, which the RP checks against `signing_key_attestation`.
    #[serde(serialize_with = "serialize_public_key")]
    #[serde(deserialize_with = "deserialize_public_key")]
    pub flamingo_verifier_key: EdDSAPublicKey,
    /// The Flamingo Verifier's time when it signed the token, in Unix seconds.
    pub now: u32,
    /// The AAT values, if the Flamingo Verifier verified an AAT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aat: Option<AatPublicValues>,
    /// The Engine configuration that ran.
    pub engine_config_hash: FieldElement,
    /// The root of the `WorldIDRegistry` tree the proof's inclusion is under.
    pub merkle_root: FieldElement,
    /// The Credential schema version.
    pub issuer_version: u8,
    /// The Issuer's key, which the RP checks it trusts for the schema and version.
    #[serde(serialize_with = "serialize_public_key")]
    #[serde(deserialize_with = "deserialize_public_key")]
    pub cred_pk: EdDSAPublicKey,
    /// The Flamingo Verifier's attestation of `flamingo_verifier_key` (WIP-201 §4.7).
    pub signing_key_attestation: Bytes,
}
