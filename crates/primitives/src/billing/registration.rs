//! What an Authenticator produces to register a World ID for a billing context (WIP-107 §§4.4–4.6).

use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};
use taceo_oprf::types::OprfKeyId;

use super::{ActivePeriods, BILLED_ACTION_PREFIX, BillingContext};
use crate::{
    FieldElement, OprfPrefixedFieldElement as _, PrimitiveError, ProofRequest, ProofType,
    ZeroKnowledgeProof, request::RequestVersion,
};

/// The `periodStart` an Authenticator without a cached registration registers under (WIP-107 §4.6):
/// the next period while it is active and has capacity left, otherwise the current one.
///
/// A cached registration for either active period takes precedence; checking the cache is the
/// caller's job.
#[must_use]
pub const fn registration_period_start(active: ActivePeriods, next_has_capacity: bool) -> u64 {
    match active.next {
        Some(next) if next_has_capacity => next,
        _ => active.current,
    }
}

/// What a Proof of Embedding Similarity needs from a billing query, which the Authenticator caches
/// per account, [`BillingContext`] and OPRF key (WIP-107 §4.6).
///
/// `billing_oprf_output` is private: with the public `billing_nullifier` it reveals the account's
/// leaf index, so `Debug` omits it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingWitness {
    /// The query's action, the context's `billingAction`.
    pub billing_action: FieldElement,
    /// The `billingNullifier` the Billing Contract registers.
    pub billing_nullifier: FieldElement,
    /// The unblinded OPRF output `R` of the billing query, as `[x, y]`.
    pub billing_oprf_output: [FieldElement; 2],
}

impl std::fmt::Debug for BillingWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BillingWitness")
            .field("billing_action", &self.billing_action)
            .field("billing_nullifier", &self.billing_nullifier)
            .finish_non_exhaustive()
    }
}

/// The RP authorization `register` checks, copied from the RP's [`ProofRequest`] (WIP-107 §4.5),
/// `RegistrationAuthorization` in the Billing Contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationAuthorization {
    /// The request version.
    pub version: RequestVersion,
    /// The RP's OPRF key.
    pub oprf_key_id: OprfKeyId,
    /// The request's nonce, which `register` consumes.
    pub nonce: FieldElement,
    /// The request's `created_at`.
    pub created_at: u64,
    /// The request's `expires_at`.
    pub expires_at: u64,
    /// The request's action, which the RP signed and whose MSB is [`BILLED_ACTION_PREFIX`].
    pub signed_action: FieldElement,
    /// The RP's signature over the request.
    #[serde(with = "crate::serde_utils::hex_signature")]
    pub signature: alloy::signers::Signature,
    /// WIP-101 data for a contract-backed RP signer; empty for an EOA signer.
    #[serde(default, skip_serializing_if = "<[u8]>::is_empty")]
    pub wip101_data: Bytes,
}

impl RegistrationAuthorization {
    /// Copies the authorization from a Proof of Embedding Similarity request.
    ///
    /// # Errors
    /// Returns [`PrimitiveError::InvalidInput`] if the request is not a Proof of Embedding
    /// Similarity request or its action does not carry [`BILLED_ACTION_PREFIX`].
    pub fn from_request(request: &ProofRequest) -> Result<Self, PrimitiveError> {
        let ProofType::EmbeddingSimilarity(params) = &request.proof_type else {
            return Err(PrimitiveError::InvalidInput {
                attribute: "proof_type".to_string(),
                reason: "only an embedding_similarity request authorizes registration".to_string(),
            });
        };
        if !params.action.has_prefix(BILLED_ACTION_PREFIX) {
            return Err(PrimitiveError::InvalidInput {
                attribute: "action".to_string(),
                reason: format!("MSB must be 0x{:02x}", BILLED_ACTION_PREFIX as u8),
            });
        }
        Ok(Self {
            version: request.version,
            oprf_key_id: request.oprf_key_id,
            nonce: request.nonce,
            created_at: request.created_at,
            expires_at: request.expires_at,
            signed_action: params.action,
            signature: request.signature,
            wip101_data: Bytes::new(),
        })
    }
}

/// The arguments of `WorldIDBilling.register` for one World ID (WIP-107 §4.2), ready to submit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingRegistration {
    /// The billing context registered for.
    pub scope: BillingContext,
    /// The RP's authorization.
    pub authorization: RegistrationAuthorization,
    /// The schema of the credential the proof uses, which need not match the RP's request.
    pub issuer_schema_id: u64,
    /// The credential expiry lower bound the proof attests.
    pub expires_at_min: u64,
    /// The `billingNullifier` to register.
    pub billing_nullifier: FieldElement,
    /// The registration proof: a Uniqueness Proof for `billingAction` with zero signal, genesis
    /// minimum and session (WIP-107 §4.4.1).
    pub proof: ZeroKnowledgeProof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EmbeddingSimilarityParams, OprfPrefix, RequestItem, SessionRef, rp::RpId};
    use alloy_primitives::{Address, U256};
    use ruint::uint;

    fn action_with_prefix(prefix: OprfPrefix) -> FieldElement {
        let mut bytes = [0x11u8; 32];
        bytes[0] = prefix as u8;
        FieldElement::from_be_bytes(&bytes).expect("in field")
    }

    fn embedding_similarity_request(action: FieldElement) -> ProofRequest {
        ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
                action,
                challenge_hash: FieldElement::from(7u64),
                aat: None,
            }),
            created_at: 1_793_534_500,
            expires_at: 1_793_534_800,
            rp_id: RpId::new(42),
            oprf_key_id: OprfKeyId::new(uint!(9_U160)),
            session_id: SessionRef::None,
            signature: alloy::signers::Signature::new(U256::from(1u64), U256::from(2u64), true),
            nonce: FieldElement::from(5u64),
            requests: vec![RequestItem {
                identifier: "poh".into(),
                issuer_schema_id: 1,
                signal: Some(b"signal".to_vec()),
                genesis_issued_at_min: Some(10),
                expires_at_min: None,
            }],
            constraints: None,
        }
    }

    #[test]
    fn registration_period_start_prefers_the_next_period_with_capacity() {
        let overlap = ActivePeriods {
            current: 100,
            next: Some(200),
        };
        assert_eq!(registration_period_start(overlap, true), 200);
        assert_eq!(registration_period_start(overlap, false), 100);
        let mid_month = ActivePeriods {
            current: 100,
            next: None,
        };
        assert_eq!(registration_period_start(mid_month, true), 100);
    }

    #[test]
    fn authorization_copies_the_request() {
        let action = action_with_prefix(OprfPrefix::EmbeddingSimilarity);
        let request = embedding_similarity_request(action);
        let authorization = RegistrationAuthorization::from_request(&request).expect("valid");
        assert_eq!(
            authorization,
            RegistrationAuthorization {
                version: RequestVersion::V1,
                oprf_key_id: request.oprf_key_id,
                nonce: request.nonce,
                created_at: request.created_at,
                expires_at: request.expires_at,
                signed_action: action,
                signature: request.signature,
                wip101_data: Bytes::new(),
            }
        );
    }

    #[test]
    fn authorization_requires_an_embedding_similarity_action() {
        let mut request =
            embedding_similarity_request(action_with_prefix(OprfPrefix::EmbeddingSimilarity));
        request.proof_type = ProofType::Uniqueness {
            action: action_with_prefix(OprfPrefix::Uniqueness),
        };
        assert!(matches!(
            RegistrationAuthorization::from_request(&request),
            Err(PrimitiveError::InvalidInput { attribute, .. }) if attribute == "proof_type"
        ));

        let request = embedding_similarity_request(action_with_prefix(OprfPrefix::Uniqueness));
        assert!(matches!(
            RegistrationAuthorization::from_request(&request),
            Err(PrimitiveError::InvalidInput { attribute, .. }) if attribute == "action"
        ));
    }

    #[test]
    fn registration_roundtrips_in_json() {
        let request =
            embedding_similarity_request(action_with_prefix(OprfPrefix::EmbeddingSimilarity));
        let registration = BillingRegistration {
            scope: BillingContext {
                chain_id: U256::from(480u64),
                billing_contract: Address::repeat_byte(0xb1),
                rp_id: RpId::new(42),
                period_start: 1_793_534_400,
            },
            authorization: RegistrationAuthorization::from_request(&request).expect("valid"),
            issuer_schema_id: 1,
            expires_at_min: request.created_at,
            billing_nullifier: FieldElement::from(77u64),
            proof: ZeroKnowledgeProof::default(),
        };
        let json = serde_json::to_value(&registration).expect("serializes");
        assert!(json["authorization"].get("wip101_data").is_none());
        let parsed: BillingRegistration = serde_json::from_value(json).expect("deserializes");
        assert_eq!(parsed, registration);
    }

    #[test]
    fn witness_debug_omits_the_oprf_output() {
        let witness = BillingWitness {
            billing_action: FieldElement::from(1u64),
            billing_nullifier: FieldElement::from(2u64),
            billing_oprf_output: [FieldElement::from(31_337u64), FieldElement::from(31_338u64)],
        };
        let debug = format!("{witness:?}");
        assert!(!debug.contains("billing_oprf_output"));
        assert!(!debug.contains(&format!("{:?}", FieldElement::from(31_337u64))));
    }
}
