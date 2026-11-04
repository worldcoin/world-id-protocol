use super::*;
use crate::{EdDSAPrivateKey, EdDSAPublicKey};
use alloy::{
    signers::{SignerSync, local::PrivateKeySigner},
    uint,
};
use k256::ecdsa::SigningKey;
use ruint::aliases::U256;
use serde_json::json;

fn field(n: u64) -> FieldElement {
    FieldElement::from(n)
}

fn action_with_prefix(prefix: OprfPrefix, n: u64) -> FieldElement {
    let v = U256::from(n) | (U256::from(prefix as u8) << 248);
    FieldElement::try_from(v).expect("test value fits in field")
}

fn params() -> EmbeddingSimilarityParams {
    EmbeddingSimilarityParams {
        action: action_with_prefix(OprfPrefix::EmbeddingSimilarity, 7),
        challenge_hash: field(0xc0ffee),
        flamingo_configurations: vec![FlamingoConfiguration {
            iss: "provider.example".into(),
            pipeline_id: 3,
            match_strictness: 2,
            min_version: 5,
        }],
        aat: Some(AatRequirements {
            required: true,
            platform: Some(2),
            sec_level: None,
            sec_meta: Some(15),
            authenticator_meta: Some(31),
        }),
    }
}

fn signature() -> alloy::signers::Signature {
    PrivateKeySigner::from_signing_key(SigningKey::from_bytes(&[1u8; 32].into()).unwrap())
        .sign_message_sync(b"test")
        .expect("can sign")
}

fn request(proof_type: ProofType, session_id: SessionRef) -> ProofRequest {
    ProofRequest {
        id: "req_es".into(),
        version: RequestVersion::V1,
        proof_type,
        session_id,
        created_at: 1_735_689_600,
        expires_at: 1_735_689_900,
        rp_id: RpId::new(1),
        oprf_key_id: OprfKeyId::new(uint!(1_U160)),
        signature: signature(),
        nonce: field(1),
        requests: vec![RequestItem {
            identifier: "poh".into(),
            issuer_schema_id: 1,
            signal: None,
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    }
}

fn es_request() -> ProofRequest {
    request(ProofType::EmbeddingSimilarity(params()), SessionRef::None)
}

fn public_key(seed: u8) -> EdDSAPublicKey {
    EdDSAPrivateKey::from_bytes([seed; 32]).public()
}

fn es_item() -> EmbeddingSimilarityResponseItem {
    EmbeddingSimilarityResponseItem {
        identifier: "poh".into(),
        issuer_schema_id: 1,
        proof: vec![1, 2, 3],
        flamingo_verifier_key: public_key(1),
        now: 1_735_689_650,
        aat: Some(AatPublicValues {
            trust_anchor_key_hash: field(9),
            platform: 2,
            sec_level: 1,
            sec_meta: 3,
            authenticator_meta: 10,
        }),
        engine_config_hash: field(10),
        merkle_root: field(11),
        issuer_version: 1,
        cred_pk: public_key(2),
        signing_key_attestation: vec![0xde, 0xad],
    }
}

fn response(items: Vec<ResponseItem>) -> ProofResponse {
    ProofResponse {
        id: "req_es".into(),
        version: RequestVersion::V1,
        session_id: None,
        error: None,
        responses: items,
    }
}

fn groth16_item() -> ResponseItem {
    ResponseItem::new_uniqueness(
        "poh".into(),
        1,
        ZeroKnowledgeProof::default(),
        field(5).into(),
        1_735_689_600,
    )
}

#[test]
fn proof_type_wire_encoding_is_flat() {
    let proof_type = ProofType::EmbeddingSimilarity(params());
    let expected = json!({
        "proof_type": "embedding_similarity",
        "action": params().action,
        "challenge_hash": params().challenge_hash,
        "flamingo_configurations": [{
            "iss": "provider.example", "pipeline_id": 3, "match_strictness": 2, "min_version": 5
        }],
        "aat": { "required": true, "platform": 2, "sec_meta": 15, "authenticator_meta": 31 },
    });
    assert_eq!(serde_json::to_value(&proof_type).unwrap(), expected);
    assert_eq!(
        serde_json::from_value::<ProofType>(expected).unwrap(),
        proof_type
    );
    assert_eq!(proof_type.as_byte(), 0x03);
    assert!(proof_type.is_embedding_similarity());
    assert_eq!(proof_type.action(), Some(params().action));
}

#[test]
fn other_proof_types_do_not_serialize_embedding_similarity_params() {
    let uniqueness = serde_json::to_value(ProofType::Uniqueness { action: field(1) }).unwrap();
    assert_eq!(
        uniqueness,
        json!({ "proof_type": "uniqueness", "action": field(1) })
    );
    let session = serde_json::to_value(ProofType::Session).unwrap();
    assert_eq!(session, json!({ "proof_type": "session", "action": null }));
}

#[test]
fn proof_type_rejects_missing_or_foreign_params() {
    let valid = serde_json::to_value(ProofType::EmbeddingSimilarity(params())).unwrap();
    for missing in ["action", "challenge_hash", "flamingo_configurations"] {
        let mut value = valid.clone();
        value.as_object_mut().unwrap().remove(missing);
        let err = serde_json::from_value::<ProofType>(value).unwrap_err();
        assert!(err.to_string().contains(missing), "{missing}: {err}");
    }

    for (proof_type, foreign) in [
        (
            json!({ "proof_type": "uniqueness", "action": field(1) }),
            "challenge_hash",
        ),
        (
            json!({ "proof_type": "session" }),
            "flamingo_configurations",
        ),
        (json!({ "proof_type": "session" }), "aat"),
    ] {
        let mut value = proof_type;
        let params = valid.as_object().unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert(foreign.into(), params[foreign].clone());
        let err = serde_json::from_value::<ProofType>(value).unwrap_err();
        assert!(err.to_string().contains(foreign), "{foreign}: {err}");
    }
}

#[test]
fn request_roundtrips_through_json() {
    let request = es_request();
    request.validate_proof_type().unwrap();
    let json = request.to_json().unwrap();
    assert_eq!(ProofRequest::from_json(&json).unwrap(), request);
}

#[test]
fn validate_proof_type_accepts_no_or_existing_session() {
    es_request().validate_proof_type().unwrap();
    let session_id =
        SessionId::new(field(7), action_with_prefix(OprfPrefix::SessionOprfSeed, 7)).unwrap();
    request(
        ProofType::EmbeddingSimilarity(params()),
        SessionRef::Existing(session_id),
    )
    .validate_proof_type()
    .unwrap();
}

#[test]
fn validate_proof_type_is_strict_for_embedding_similarity() {
    let invalid = |mut request: ProofRequest, attribute: &str| {
        let err = request.validate_proof_type().unwrap_err();
        assert!(
            matches!(&err, PrimitiveError::InvalidInput { attribute: a, .. } if a == attribute),
            "{attribute}: {err}"
        );
        // `from_json` runs the same check.
        request.signature = signature();
        assert!(ProofRequest::from_json(&request.to_json().unwrap()).is_err());
    };
    let with = |edit: &dyn Fn(&mut EmbeddingSimilarityParams)| {
        let mut p = params();
        edit(&mut p);
        request(ProofType::EmbeddingSimilarity(p), SessionRef::None)
    };

    for prefix in [
        OprfPrefix::Uniqueness,
        OprfPrefix::SessionOprfSeed,
        OprfPrefix::SessionAction,
    ] {
        invalid(
            with(&|p| p.action = action_with_prefix(prefix, 7)),
            "action",
        );
    }
    invalid(
        with(&|p| p.challenge_hash = FieldElement::ZERO),
        "challenge_hash",
    );
    invalid(
        with(&|p| p.flamingo_configurations.clear()),
        "flamingo_configurations",
    );
    invalid(
        with(&|p| {
            let one = p.flamingo_configurations[0].clone();
            p.flamingo_configurations = vec![one; MAX_FLAMINGO_CONFIGURATIONS + 1];
        }),
        "flamingo_configurations",
    );
    invalid(
        with(&|p| p.aat.as_mut().unwrap().sec_meta = Some(16)),
        "aat.sec_meta",
    );
    invalid(
        with(&|p| p.aat.as_mut().unwrap().authenticator_meta = Some(32)),
        "aat.authenticator_meta",
    );
    invalid(
        request(ProofType::EmbeddingSimilarity(params()), SessionRef::Create),
        "session_id",
    );

    let mut two_items = es_request();
    two_items
        .requests
        .push(RequestItem::new("other".into(), 2, None, None, None));
    invalid(two_items, "proof_requests");
    let mut no_items = es_request();
    no_items.requests.clear();
    invalid(no_items, "proof_requests");
    let mut constrained = es_request();
    constrained.constraints = Some(ConstraintExpr::All {
        all: vec![ConstraintNode::Type("poh".into())],
    });
    invalid(constrained, "constraints");
}

#[test]
fn validate_proof_type_accepts_the_largest_values() {
    let mut p = params();
    p.flamingo_configurations =
        vec![p.flamingo_configurations[0].clone(); MAX_FLAMINGO_CONFIGURATIONS];
    p.aat = Some(AatRequirements {
        sec_meta: Some(15),
        authenticator_meta: Some(31),
        ..AatRequirements::default()
    });
    request(ProofType::EmbeddingSimilarity(p), SessionRef::None)
        .validate_proof_type()
        .unwrap();
}

#[test]
fn rp_signature_digest_covers_the_action() {
    let digest = |action: FieldElement| {
        let mut p = params();
        p.action = action;
        request(ProofType::EmbeddingSimilarity(p), SessionRef::None)
            .digest_hash()
            .unwrap()
    };
    let a = action_with_prefix(OprfPrefix::EmbeddingSimilarity, 1);
    let b = action_with_prefix(OprfPrefix::EmbeddingSimilarity, 2);
    assert_eq!(digest(a), digest(a));
    assert_ne!(digest(a), digest(b));

    // The digest is that of a uniqueness request with the same action.
    let uniqueness = request(ProofType::Uniqueness { action: a }, SessionRef::None);
    assert_eq!(digest(a), uniqueness.digest_hash().unwrap());
}

#[test]
fn response_item_wire_encoding() {
    let es = ResponseItem::EmbeddingSimilarity(es_item());
    let value = serde_json::to_value(&es).unwrap();
    assert_eq!(value["proof_type"], "embedding_similarity");
    assert_eq!(value["proof"], "0x010203");
    assert_eq!(value["signing_key_attestation"], "0xdead");
    assert_eq!(value["now"], 1_735_689_650);
    assert_eq!(value["aat"]["platform"], 2);
    let decoded: ResponseItem = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.as_embedding_similarity(), Some(&es_item()));
    assert!(decoded.is_embedding_similarity());
    assert!(!decoded.is_uniqueness() && !decoded.is_session());
    assert_eq!(decoded.identifier(), "poh");
    assert_eq!(decoded.issuer_schema_id(), 1);

    // Without an AAT, `aat` is absent.
    let mut no_aat = es_item();
    no_aat.aat = None;
    let value = serde_json::to_value(ResponseItem::EmbeddingSimilarity(no_aat)).unwrap();
    assert!(value.get("aat").is_none());
    let decoded: ResponseItem = serde_json::from_value(value).unwrap();
    assert!(decoded.as_embedding_similarity().unwrap().aat.is_none());
}

#[test]
fn groth16_response_item_wire_encoding_is_unchanged() {
    let item = groth16_item();
    let value = serde_json::to_value(&item).unwrap();
    assert!(value.get("proof_type").is_none());
    assert!(value.get("nullifier").is_some());
    let decoded: ResponseItem = serde_json::from_value(value).unwrap();
    assert!(decoded.is_uniqueness());
    assert_eq!(decoded.as_groth16().unwrap().expires_at_min, 1_735_689_600);
    assert!(decoded.as_embedding_similarity().is_none());
}

#[test]
fn response_item_rejects_a_truncated_embedding_similarity_item() {
    let mut value = serde_json::to_value(ResponseItem::EmbeddingSimilarity(es_item())).unwrap();
    value.as_object_mut().unwrap().remove("merkle_root");
    assert!(serde_json::from_value::<ResponseItem>(value).is_err());
}

#[test]
fn response_item_rejects_a_malformed_key() {
    let mut value = serde_json::to_value(ResponseItem::EmbeddingSimilarity(es_item())).unwrap();
    value["cred_pk"] = json!("0x00");
    assert!(serde_json::from_value::<ResponseItem>(value).is_err());
}

#[test]
fn response_json_roundtrip_with_embedding_similarity_item() {
    let response = response(vec![ResponseItem::EmbeddingSimilarity(es_item())]);
    let json = response.to_json_pretty().unwrap();
    let decoded = ProofResponse::from_json(&json).unwrap();
    assert_eq!(decoded.successful_credentials(), vec![1]);
    assert_eq!(
        decoded.responses[0].as_embedding_similarity(),
        Some(&es_item())
    );
}

#[test]
fn validate_response_accepts_an_embedding_similarity_item() {
    es_request()
        .validate_response(&response(vec![
            ResponseItem::EmbeddingSimilarity(es_item()),
        ]))
        .unwrap();
}

#[test]
fn validate_response_rejects_an_item_of_the_wrong_kind() {
    let err = es_request()
        .validate_response(&response(vec![groth16_item()]))
        .unwrap_err();
    assert_eq!(err, ValidationError::ResponseItemTypeMismatch("poh".into()));

    let uniqueness = request(
        ProofType::Uniqueness { action: field(42) },
        SessionRef::None,
    );
    let err = uniqueness
        .validate_response(&response(vec![
            ResponseItem::EmbeddingSimilarity(es_item()),
        ]))
        .unwrap_err();
    assert_eq!(err, ValidationError::ResponseItemTypeMismatch("poh".into()));
}

#[test]
fn validate_response_checks_the_item_identifier() {
    let mut item = es_item();
    item.identifier = "other".into();
    let err = es_request()
        .validate_response(&response(vec![ResponseItem::EmbeddingSimilarity(item)]))
        .unwrap_err();
    assert_eq!(err, ValidationError::UnexpectedCredential("other".into()));

    let err = es_request()
        .validate_response(&response(vec![]))
        .unwrap_err();
    assert_eq!(err, ValidationError::MissingCredential("poh".into()));

    let item = ResponseItem::EmbeddingSimilarity(es_item());
    let err = es_request()
        .validate_response(&response(vec![item.clone(), item]))
        .unwrap_err();
    assert_eq!(err, ValidationError::DuplicateCredential("poh".into()));
}

#[test]
fn validate_response_checks_the_session() {
    let item = || ResponseItem::EmbeddingSimilarity(es_item());
    let session_id =
        SessionId::new(field(7), action_with_prefix(OprfPrefix::SessionOprfSeed, 7)).unwrap();
    let other_session_id =
        SessionId::new(field(8), action_with_prefix(OprfPrefix::SessionOprfSeed, 8)).unwrap();

    // Without a session the response carries none.
    let mut with_session = response(vec![item()]);
    with_session.session_id = Some(session_id);
    assert_eq!(
        es_request().validate_response(&with_session).unwrap_err(),
        ValidationError::UnexpectedSessionId
    );

    // With an existing session the response echoes it.
    let existing = request(
        ProofType::EmbeddingSimilarity(params()),
        SessionRef::Existing(session_id),
    );
    existing.validate_response(&with_session).unwrap();
    assert_eq!(
        existing
            .validate_response(&response(vec![item()]))
            .unwrap_err(),
        ValidationError::SessionIdMismatch
    );
    with_session.session_id = Some(other_session_id);
    assert_eq!(
        existing.validate_response(&with_session).unwrap_err(),
        ValidationError::SessionIdMismatch
    );
}

#[test]
fn validate_response_rejects_a_request_that_is_not_valid() {
    let mut p = params();
    p.challenge_hash = FieldElement::ZERO;
    let invalid = request(ProofType::EmbeddingSimilarity(p), SessionRef::None);
    let err = invalid
        .validate_response(&response(vec![
            ResponseItem::EmbeddingSimilarity(es_item()),
        ]))
        .unwrap_err();
    assert!(matches!(err, ValidationError::InvalidProofRequest(_)));
}

#[test]
fn field_element_prefix_helper_matches_the_action_prefix() {
    assert!(params().action.has_prefix(OprfPrefix::EmbeddingSimilarity));
}
