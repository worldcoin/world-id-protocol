use super::*;
use p256::ecdsa::{SigningKey, signature::Signer as _};

const KID: &str = "release-1";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32].into()).unwrap()
}

fn jwk(key: &SigningKey, kid: &str) -> ReleaseKeyJwk {
    let point = key.verifying_key().to_encoded_point(false);
    ReleaseKeyJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        kid: kid.into(),
    }
}

fn payload() -> ManifestPayload {
    ManifestPayload {
        engine_hash: "2a".repeat(32),
        version: "1.0.0".into(),
        pipelines: vec![Pipeline {
            pipeline: 1,
            description: "credential image, live capture, challenge".into(),
            response_slots: ResponseSlots {
                min: 500,
                max: 16_000,
                count: 4,
            },
            max_request_bytes: 8 << 20,
        }],
        match_strictness_levels: vec![
            MatchStrictnessLevel {
                match_strictness: 1,
                description: "loose".into(),
            },
            MatchStrictnessLevel {
                match_strictness: 2,
                description: "strict".into(),
            },
        ],
    }
}

fn sign_raw(header: &str, payload: &[u8], key: &SigningKey) -> String {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn header(alg: &str, typ: &str) -> String {
    format!(r#"{{"alg":"{alg}","kid":"{KID}","typ":"{typ}"}}"#)
}

fn sign(payload: &ManifestPayload) -> String {
    sign_raw(
        &header("ES256", MANIFEST_TYP),
        &serde_json::to_vec(payload).unwrap(),
        &signing_key(),
    )
}

#[test]
fn parses_and_verifies_a_manifest() {
    let compact = sign(&payload());
    let manifest = ReleaseManifest::parse(&compact).unwrap();
    assert_eq!(manifest.kid(), KID);
    assert_eq!(manifest.payload(), &payload());
    assert_eq!(manifest.payload().engine_hash(), Some([0x2a; 32]));
    assert!(manifest.verify(&jwk(&signing_key(), KID)).is_ok());
    assert!(manifest.pipeline(1).is_some() && manifest.pipeline(2).is_none());
    assert!(manifest.defines_strictness(2) && !manifest.defines_strictness(3));
    assert_eq!(manifest.max_request_bytes(), 8 << 20);
}

#[test]
fn release_hash_covers_only_the_payload() {
    let bytes = serde_json::to_vec(&payload()).unwrap();
    let manifest = ReleaseManifest::parse(&sign(&payload())).unwrap();
    assert_eq!(
        manifest.release_hash(),
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );

    // Re-signing with another key keeps the hash.
    let other_key = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
    let resigned = sign_raw(&header("ES256", MANIFEST_TYP), &bytes, &other_key);
    let resigned = ReleaseManifest::parse(&resigned).unwrap();
    assert_eq!(resigned.release_hash(), manifest.release_hash());
}

#[test]
fn rejects_other_keys_and_tampered_payloads() {
    let manifest = ReleaseManifest::parse(&sign(&payload())).unwrap();
    let other = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
    assert_eq!(
        manifest.verify(&jwk(&other, KID)),
        Err(ManifestError::SignatureInvalid)
    );
    assert_eq!(
        manifest.verify(&jwk(&signing_key(), "other")),
        Err(ManifestError::SignatureInvalid)
    );

    let compact = sign(&payload());
    let (header, rest) = compact.split_once('.').unwrap();
    let (_, signature) = rest.split_once('.').unwrap();
    let mut changed = payload();
    changed.version = "1.0.1".into();
    let tampered = format!(
        "{header}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap())
    );
    let tampered = ReleaseManifest::parse(&tampered).unwrap();
    assert_eq!(
        tampered.verify(&jwk(&signing_key(), KID)),
        Err(ManifestError::SignatureInvalid)
    );
}

#[test]
fn rejects_other_headers() {
    let bytes = serde_json::to_vec(&payload()).unwrap();
    for header in [header("HS256", MANIFEST_TYP), header("ES256", "JWT")] {
        let compact = sign_raw(&header, &bytes, &signing_key());
        assert!(matches!(
            ReleaseManifest::parse(&compact),
            Err(ManifestError::Malformed(_))
        ));
    }
    assert!(ReleaseManifest::parse("a.b").is_err());
}

type Change = Box<dyn Fn(&mut ManifestPayload)>;

#[test]
fn rejects_payloads_that_break_the_rules() {
    let slots = |min, max, count| ResponseSlots { min, max, count };
    let cases: Vec<(Change, &str)> = vec![
        (Box::new(|p| p.engine_hash = "2A".repeat(32)), "engine_hash"),
        (Box::new(|p| p.engine_hash = "2a".repeat(31)), "engine_hash"),
        (Box::new(|p| p.pipelines.clear()), "pipelines"),
        (
            Box::new(|p| p.pipelines.push(p.pipelines[0].clone())),
            "pipeline",
        ),
        (Box::new(|p| p.pipelines[0].pipeline = 0), "pipeline"),
        (
            Box::new(move |p| p.pipelines[0].response_slots = slots(0, 10, 2)),
            "response_slots",
        ),
        (
            Box::new(move |p| p.pipelines[0].response_slots = slots(10, 5, 2)),
            "response_slots",
        ),
        (
            Box::new(move |p| p.pipelines[0].response_slots = slots(10, 10, 2)),
            "response_slots",
        ),
        (
            Box::new(move |p| p.pipelines[0].response_slots = slots(10, 20, 0)),
            "response_slots",
        ),
        (
            Box::new(|p| p.pipelines[0].max_request_bytes = 0),
            "max_request_bytes",
        ),
        (
            Box::new(|p| p.match_strictness_levels.reverse()),
            "match_strictness_levels",
        ),
        (
            Box::new(|p| p.match_strictness_levels[1].match_strictness = 1),
            "match_strictness_levels",
        ),
    ];
    for (change, field) in cases {
        let mut payload = payload();
        change(&mut payload);
        assert_eq!(
            ReleaseManifest::parse(&sign(&payload)),
            Err(ManifestError::Invalid(field))
        );
    }
}

#[test]
fn allows_a_single_slot() {
    let mut payload = payload();
    payload.pipelines[0].response_slots = ResponseSlots {
        min: 3000,
        max: 3000,
        count: 1,
    };
    assert!(ReleaseManifest::parse(&sign(&payload)).is_ok());
}

#[test]
fn computes_geometric_slots() {
    let slots = ResponseSlots {
        min: 500,
        max: 16_000,
        count: 4,
    };
    assert_eq!(slots.times(), vec![500, 1587, 5039, 16_000]);
    assert_eq!(slots.release_at(0), Some(500));
    assert_eq!(slots.release_at(500), Some(500));
    assert_eq!(slots.release_at(1600), Some(5039));
    assert_eq!(slots.release_at(16_001), None);
    assert!((slots.leakage_bits() - 2.0).abs() < f64::EPSILON);

    let single = ResponseSlots {
        min: 1,
        max: 3000,
        count: 1,
    };
    assert_eq!(single.times(), vec![3000]);
    assert!(single.leakage_bits().abs() < f64::EPSILON);
}

#[test]
fn reads_active_manifests_from_metadata() {
    let active = sign(&payload());
    let mut retired_payload = payload();
    retired_payload.version = "0.9.0".into();
    let retired = sign(&retired_payload);
    let other_key = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
    let unsigned = sign_raw(
        &header("ES256", MANIFEST_TYP),
        &serde_json::to_vec(&payload()).unwrap(),
        &other_key,
    );
    let metadata = EngineMetadata {
        version: 1,
        provider_id: "example".into(),
        release_keys: vec![ReleaseKey {
            jwk: jwk(&signing_key(), KID),
            status: ReleaseStatus::Active,
        }],
        manifests: vec![
            MetadataManifest {
                manifest: active.clone(),
                status: ReleaseStatus::Active,
            },
            MetadataManifest {
                manifest: retired,
                status: ReleaseStatus::Retired,
            },
            MetadataManifest {
                manifest: unsigned,
                status: ReleaseStatus::Active,
            },
        ],
    };
    let parsed = EngineMetadata::parse(&serde_json::to_vec(&metadata).unwrap()).unwrap();
    let manifests = parsed.active_manifests();
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].as_str(), active);

    let mut wrong_version = metadata;
    wrong_version.version = 2;
    assert_eq!(
        EngineMetadata::parse(&serde_json::to_vec(&wrong_version).unwrap()),
        Err(ManifestError::Invalid("metadata version"))
    );
}
