use super::*;
use world_id_primitives::EdDSAPrivateKey;

// WIP-201 Appendix A1, "With an AAT".
const PAYLOAD: &str = "a66568696e74734067636f6d706172658300010267656e747269657383a264646174615063726564656e7469616c20696d616765646d65746140a264646174614a6c69766520696d616765646d65746140a264646174614f6368616c6c656e676520696d616765646d6574614068706970656c696e65016c72656c656173655f6861736858202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a706d617463685f7374726963746e65737302";
const CDH: &str = "06559c686e02e6fdd317c3faf3d3a871f1660465552dc3c15e36290a44346150";
const AAT_SIG: &str = "c16ec4215ef7b7b26655ddbf5858e008027aec5326da024ca89c605981e25b249797ee4fb67583591217114e3ba7d9e470e0abada652ec27236992a5854c0a04";
const PROVIDER_KEY_HASH: &str = "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
const COMPARED: [&str; 3] = [
    "21e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c415",
    "010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b",
    "2abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d",
];

fn hex_field(hex: &str) -> FieldElement {
    FieldElement::from_be_bytes(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
}

fn payload() -> Payload {
    let entry = |data: &[u8]| Entry {
        data: data.to_vec(),
        meta: vec![],
    };
    Payload {
        pipeline: 1,
        match_strictness: 2,
        hints: vec![],
        entries: vec![
            entry(b"credential image"),
            entry(b"live image"),
            entry(b"challenge image"),
        ],
        compare: vec![0, 1, 2],
        release_hash: [0x2a; 32],
    }
}

fn aat_inputs() -> AatInputs {
    let mut blind = [0u8; 32];
    blind[31] = 7;
    AatInputs {
        authenticator_provider_key: EdDSAPrivateKey::from_bytes([0x07; 32])
            .public()
            .to_compressed_bytes()
            .unwrap(),
        exp: 1_783_446_925,
        sec_flags: 0x0013_0000_07d6_0102,
        sig: hex::decode(AAT_SIG).unwrap().try_into().unwrap(),
        blind: FieldElement::from_be_bytes(&blind).unwrap(),
        now: 1_783_446_000,
        min_build_version: 2006,
    }
}

fn request(aat: Option<AatInputs>) -> Request {
    Request::new(1_928_118u64.into(), 42u64.into(), &payload(), aat).unwrap()
}

#[test]
fn payload_matches_the_vector() {
    let request = request(None);
    assert_eq!(hex::encode(&request.payload), PAYLOAD);
    assert_eq!(request.cdh(), hex_field(CDH));
    assert_eq!(Payload::decode(&request.payload), Ok(payload()));
}

#[test]
fn compared_entry_hashes_match_the_vector() {
    let hashes = payload().compared_entry_hashes();
    for (hash, expected) in hashes.iter().zip(COMPARED) {
        assert_eq!(*hash, hex_field(expected));
    }
    assert_eq!(hashes[3], FieldElement::ZERO);
}

#[test]
fn verifies_the_vector_aat() {
    let claims = request(Some(aat_inputs())).verify_aat().unwrap().unwrap();
    assert_eq!(
        claims,
        AatClaims {
            authenticator_provider_key_hash: hex_field(PROVIDER_KEY_HASH),
            aat_flags: 0x0013_0000_07d6_0102,
            now: 1_783_446_000,
        }
    );
    assert_eq!(request(None).verify_aat(), Ok(None));
}

#[test]
fn rejects_an_aat_for_another_payload() {
    let mut other = payload();
    other.hints = vec![1];
    let request = Request::new(
        1_928_118u64.into(),
        42u64.into(),
        &other,
        Some(aat_inputs()),
    )
    .unwrap();
    assert!(matches!(
        request.verify_aat(),
        Err(RequestError::AatRejected(_))
    ));
}

#[test]
fn requests_round_trip() {
    for request in [request(None), request(Some(aat_inputs()))] {
        assert_eq!(Request::decode(&request.encode()), Ok(request));
    }
}

type Case = (fn(&mut Payload), &'static str);

#[test]
fn rejects_payloads_out_of_bounds() {
    let cases: [Case; 9] = [
        (|p| p.pipeline = 0, "pipeline"),
        (|p| p.hints = vec![0; MAX_HINTS_BYTES + 1], "hints"),
        (|p| p.entries.clear(), "entries"),
        (
            |p| p.entries[0].meta = vec![0; MAX_ENTRY_META_BYTES + 1],
            "entries[].meta",
        ),
        (|p| p.compare = vec![0], "compare"),
        (|p| p.compare = vec![0, 1, 2, 0, 1], "compare"),
        (|p| p.compare = vec![0, 0], "compare"),
        (|p| p.compare = vec![0, 3], "compare"),
        (
            |p| {
                p.entries.resize(
                    MAX_ENTRIES + 1,
                    Entry {
                        data: vec![],
                        meta: vec![],
                    },
                );
            },
            "entries",
        ),
    ];
    for (change, field) in cases {
        let mut payload = payload();
        change(&mut payload);
        assert_eq!(payload.encode(), Err(RequestError::OutOfBounds(field)));
    }
}

#[test]
fn rejects_a_zero_nonce() {
    assert_eq!(
        Request::new(1u64.into(), FieldElement::ZERO, &payload(), None),
        Err(RequestError::OutOfBounds("nonce"))
    );
}

/// Re-encodes a canonical map with its entries reversed.
fn reversed(bytes: &[u8]) -> Vec<u8> {
    let mut value: Value = ciborium::from_reader(bytes).unwrap();
    if let Value::Map(entries) = &mut value {
        entries.reverse();
    }
    cbor::encode(&value)
}

/// Re-encodes a canonical map with `key` set to `value`.
fn with(bytes: &[u8], key: &str, value: Value) -> Vec<u8> {
    let mut map: Value = ciborium::from_reader(bytes).unwrap();
    if let Value::Map(entries) = &mut map {
        match entries.iter_mut().find(|(k, _)| k.as_text() == Some(key)) {
            Some(entry) => entry.1 = value,
            None => entries.push((Value::Text(key.into()), value)),
        }
    }
    cbor::encode(&map)
}

#[test]
fn rejects_non_canonical_or_foreign_encodings() {
    let encoded = request(Some(aat_inputs())).encode();
    let payload = request(None).payload;
    for bytes in [
        reversed(&encoded),
        with(&encoded, "version", Value::Integer(2.into())),
        with(&encoded, "extra", Value::Integer(1.into())),
        with(&encoded, "aud", Value::Bytes(vec![0xff; 32])),
        with(&encoded, "payload", Value::Bytes(reversed(&payload))),
    ] {
        assert!(matches!(
            Request::decode(&bytes),
            Err(RequestError::Malformed(_))
        ));
    }
    for bytes in [
        reversed(&payload),
        with(&payload, "release_hash", Value::Bytes(vec![0x2a; 31])),
        with(&payload, "pipeline", Value::Integer(65_536.into())),
    ] {
        assert!(matches!(
            Payload::decode(&bytes),
            Err(RequestError::Malformed(_))
        ));
    }
}
