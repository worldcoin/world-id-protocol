//! WIP-203 Embedding Similarity proof requests and responses.

use alloy_primitives::{B256, Bytes};
use serde::{Deserialize, Serialize};

use super::{RequestItem, ValidationError};
use crate::FieldElement;

/// The `embedding_similarity` object of a [`ProofType::EmbeddingSimilarity`](super::ProofType)
/// request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingSimilarityRequest {
    /// `R(SHA-256(challenge))` of the challenge image the RP checked (WIP-202 §4.3).
    pub challenge_hash: FieldElement,
    /// Accepted Flamingo configurations, most preferred first (WIP-201 §3.5.3).
    pub engine_configs: Vec<EngineConfig>,
    /// AAT requirements. Absent accepts proofs without an AAT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aat: Option<AatRequirements>,
}

/// One Flamingo configuration an RP accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineConfig {
    /// `SHA-256` of the Engine bundle, as listed in its release manifest.
    pub engine_hash: B256,
    /// Pipeline identifier within that release.
    pub pipeline: u32,
    /// Match strictness level within that release.
    pub match_strictness: u8,
}

/// AAT requirements of an embedding similarity request (WIP-106).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AatRequirements {
    /// Whether the RP rejects proofs without an AAT.
    pub required: bool,
    /// Accepted `authenticator_provider_key_hash` values.
    pub authenticator_provider_key_hashes: Vec<FieldElement>,
    /// Accepted `platform` values; empty accepts every value.
    #[serde(default)]
    pub platforms: Vec<u8>,
    /// Accepted `sec_level` values; empty accepts every value.
    #[serde(default)]
    pub sec_levels: Vec<u8>,
    /// Accepted `user_presence` values; empty accepts every value.
    #[serde(default)]
    pub user_presence: Vec<u8>,
    /// Minimum `build_version`; `0` sets no minimum.
    #[serde(default)]
    pub min_build_version: u32,
}

/// The answer to an embedding similarity request: the WIP-202 proof and the public inputs
/// the RP cannot take from its own request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingSimilarityResponse {
    /// The request item's identifier.
    pub identifier: String,
    /// The Credential's `issuer_schema_id`.
    pub issuer_schema_id: u64,
    /// The Credential's schema version.
    pub issuer_version: u8,
    /// The WIP-202 proof from ProveKit.
    pub proof: provekit_common::WhirR1CSProof,
    /// `WorldIDRegistry` root the proof was generated against.
    pub merkle_root: FieldElement,
    /// Proof time in seconds since the Unix epoch; the AAT's `now` when an AAT is present.
    pub now: u32,
    /// The configuration that ran; one of the request's `engine_configs`.
    pub engine_config: EngineConfig,
    /// The Flamingo Verifier's compressed BabyJubJub signing key.
    pub verifier_key: B256,
    /// AWS Nitro attestation document for `verifier_key` (WIP-201 §5).
    pub signing_key_attestation: Bytes,
    /// Public values of the verified AAT; absent when the Flamingo Token has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aat: Option<AatOutputs>,
}

/// Public AAT values of an embedding similarity proof (WIP-201 §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AatOutputs {
    /// WIP-106 hash of the Authenticator Provider key.
    pub authenticator_provider_key_hash: FieldElement,
    /// Platform of the Authenticator.
    pub platform: u8,
    /// Class of integrity evidence the Authenticator Provider verified.
    pub sec_level: u8,
    /// 3-bit `sec_meta` bitmask.
    pub sec_meta: u8,
    /// Reported user presence.
    pub user_presence: u8,
}

impl EmbeddingSimilarityRequest {
    /// Checks the parts of `response` this request determines (WIP-203 §3.5).
    ///
    /// The proof itself, `now`, `merkle_root`, the Issuer key and the attestation are checked
    /// by the RP's verifier, which needs a clock, the registries and the trusted PCRs.
    ///
    /// # Errors
    /// Returns a [`ValidationError`] if the response does not answer this request.
    pub fn validate_response(
        &self,
        item: &RequestItem,
        response: &EmbeddingSimilarityResponse,
    ) -> Result<(), ValidationError> {
        if response.identifier != item.identifier
            || response.issuer_schema_id != item.issuer_schema_id
        {
            return Err(ValidationError::UnexpectedCredential(
                response.identifier.clone(),
            ));
        }
        if !self.engine_configs.contains(&response.engine_config) {
            return Err(ValidationError::EngineConfigNotOffered);
        }
        match (&self.aat, &response.aat) {
            (None, None) => Ok(()),
            (Some(requirements), None) if !requirements.required => Ok(()),
            (Some(requirements), Some(aat)) if requirements.accepts(aat) => Ok(()),
            _ => Err(ValidationError::AatNotAccepted),
        }
    }
}

impl AatRequirements {
    /// Whether `aat` meets these requirements; `min_build_version` is a circuit input.
    #[must_use]
    pub fn accepts(&self, aat: &AatOutputs) -> bool {
        let allowed = |accepted: &[u8], value: u8| accepted.is_empty() || accepted.contains(&value);
        self.authenticator_provider_key_hashes
            .contains(&aat.authenticator_provider_key_hash)
            && allowed(&self.platforms, aat.platform)
            && allowed(&self.sec_levels, aat.sec_level)
            && allowed(&self.user_presence, aat.user_presence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SessionId, SessionRef,
        request::{ProofRequest, ProofResponse, ProofType, RequestVersion, ResponseItem},
        rp::RpId,
    };
    use alloy::{
        signers::{SignerSync, local::PrivateKeySigner},
        uint,
    };
    use k256::ecdsa::SigningKey;
    use taceo_oprf::types::OprfKeyId;

    const KEY_HASH: u64 = 7;

    fn config(pipeline: u32) -> EngineConfig {
        EngineConfig {
            engine_hash: B256::repeat_byte(0x2a),
            pipeline,
            match_strictness: 2,
        }
    }

    fn session_id() -> SessionId {
        let seed = uint!(0x0100000000000000000000000000000000000000000000000000000000000001_U256);
        SessionId::new(FieldElement::from(3u64), seed.try_into().unwrap()).unwrap()
    }

    fn request(aat: Option<AatRequirements>) -> ProofRequest {
        let signer =
            PrivateKeySigner::from_signing_key(SigningKey::from_bytes(&[1u8; 32].into()).unwrap());
        ProofRequest {
            id: "req_es".into(),
            version: RequestVersion::V1,
            proof_type: ProofType::EmbeddingSimilarity,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_900,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: SessionRef::None,
            action: None,
            signature: signer.sign_message_sync(b"test").unwrap(),
            nonce: FieldElement::from(1u64),
            requests: vec![RequestItem::new("poh".into(), 1, None, None, None)],
            constraints: None,
            embedding_similarity: Some(EmbeddingSimilarityRequest {
                challenge_hash: FieldElement::from(5u64),
                engine_configs: vec![config(1), config(2)],
                aat,
            }),
        }
    }

    fn requirements(required: bool) -> AatRequirements {
        AatRequirements {
            required,
            authenticator_provider_key_hashes: vec![FieldElement::from(KEY_HASH)],
            platforms: vec![2, 4],
            sec_levels: vec![],
            user_presence: vec![2],
            min_build_version: 0,
        }
    }

    fn aat(key_hash: u64, platform: u8) -> AatOutputs {
        AatOutputs {
            authenticator_provider_key_hash: FieldElement::from(key_hash),
            platform,
            sec_level: 1,
            sec_meta: 0,
            user_presence: 2,
        }
    }

    fn response(aat: Option<AatOutputs>) -> ProofResponse {
        ProofResponse {
            id: "req_es".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![],
            embedding_similarity: Some(EmbeddingSimilarityResponse {
                identifier: "poh".into(),
                issuer_schema_id: 1,
                issuer_version: 1,
                proof: provekit_common::WhirR1CSProof {
                    narg_string: vec![1],
                    hints: vec![],
                    #[cfg(debug_assertions)]
                    pattern: vec![],
                },
                merkle_root: FieldElement::from(9u64),
                now: 1_735_689_700,
                engine_config: config(2),
                verifier_key: B256::repeat_byte(1),
                signing_key_attestation: Bytes::from_static(&[0xd2]),
                aat,
            }),
        }
    }

    fn rejects(request: &ProofRequest, attribute: &str) {
        assert!(matches!(
            request.validate_proof_type(),
            Err(crate::PrimitiveError::InvalidInput { attribute: a, .. }) if a == attribute
        ));
    }

    #[test]
    fn proof_type_encoding() {
        assert_eq!(ProofType::EmbeddingSimilarity as u8, 0x10);
        assert_eq!(
            serde_json::to_string(&ProofType::EmbeddingSimilarity).unwrap(),
            "\"embedding_similarity\""
        );
    }

    #[test]
    fn request_json_roundtrip() {
        let request = request(Some(requirements(true)));
        let json = request.to_json().unwrap();
        assert_eq!(ProofRequest::from_json(&json).unwrap(), request);
    }

    #[test]
    fn validates_the_request_shape() {
        let valid = request(None);
        assert!(valid.validate_proof_type().is_ok());
        assert!(
            ProofRequest {
                session_id: SessionRef::Existing(session_id()),
                ..valid.clone()
            }
            .validate_proof_type()
            .is_ok()
        );

        rejects(
            &ProofRequest {
                action: Some(FieldElement::ZERO),
                ..valid.clone()
            },
            "action",
        );
        rejects(
            &ProofRequest {
                session_id: SessionRef::Create,
                ..valid.clone()
            },
            "session_id",
        );
        rejects(
            &ProofRequest {
                embedding_similarity: None,
                ..valid.clone()
            },
            "embedding_similarity",
        );
        rejects(
            &ProofRequest {
                proof_type: ProofType::Session,
                session_id: SessionRef::Create,
                ..valid.clone()
            },
            "embedding_similarity",
        );
        let mut two_items = valid;
        two_items.requests.push(two_items.requests[0].clone());
        rejects(&two_items, "proof_requests");
    }

    #[test]
    fn accepts_a_matching_response() {
        assert_eq!(request(None).validate_response(&response(None)), Ok(()));
        assert_eq!(
            request(Some(requirements(false))).validate_response(&response(None)),
            Ok(())
        );
        assert_eq!(
            request(Some(requirements(true))).validate_response(&response(Some(aat(KEY_HASH, 4)))),
            Ok(())
        );

        let mut request = request(None);
        request.session_id = SessionRef::Existing(session_id());
        let mut response = response(None);
        response.session_id = Some(session_id());
        assert_eq!(request.validate_response(&response), Ok(()));
    }

    #[test]
    fn rejects_a_response_outside_the_request() {
        let mut other_config = response(None);
        other_config
            .embedding_similarity
            .as_mut()
            .unwrap()
            .engine_config = config(3);
        let mut other_item = response(None);
        other_item
            .embedding_similarity
            .as_mut()
            .unwrap()
            .issuer_schema_id = 2;
        let mut missing = response(None);
        missing.embedding_similarity = None;
        let mut extra_item = response(None);
        extra_item.responses.push(ResponseItem::new_uniqueness(
            "poh".into(),
            1,
            crate::ZeroKnowledgeProof::default(),
            FieldElement::ONE.into(),
            0,
        ));
        let mut session = response(None);
        session.session_id = Some(session_id());

        let required = request(Some(requirements(true)));
        for (request, response, error) in [
            (
                request(None),
                other_config,
                ValidationError::EngineConfigNotOffered,
            ),
            (
                request(None),
                other_item,
                ValidationError::UnexpectedCredential("poh".into()),
            ),
            (
                request(None),
                missing,
                ValidationError::MissingCredential("poh".into()),
            ),
            (
                request(None),
                extra_item,
                ValidationError::UnexpectedCredential("poh".into()),
            ),
            (request(None), session, ValidationError::UnexpectedSessionId),
            (
                request(None),
                response(Some(aat(KEY_HASH, 4))),
                ValidationError::AatNotAccepted,
            ),
            (
                required.clone(),
                response(None),
                ValidationError::AatNotAccepted,
            ),
            (
                required.clone(),
                response(Some(aat(KEY_HASH + 1, 4))),
                ValidationError::AatNotAccepted,
            ),
            (
                required,
                response(Some(aat(KEY_HASH, 6))),
                ValidationError::AatNotAccepted,
            ),
        ] {
            assert_eq!(request.validate_response(&response), Err(error));
        }
    }

    #[test]
    fn rejects_an_answer_to_another_proof_type() {
        let mut uniqueness = request(None);
        uniqueness.proof_type = ProofType::Uniqueness;
        uniqueness.action = Some(FieldElement::ZERO);
        uniqueness.embedding_similarity = None;
        assert_eq!(
            uniqueness.validate_response(&response(None)),
            Err(ValidationError::UnexpectedEmbeddingSimilarity)
        );
    }
}
