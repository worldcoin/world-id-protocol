use std::{collections::BTreeMap, env, fs, path::PathBuf};

use coset::{CborSerializable as _, CoseSign1};
use eddsa_babyjubjub::EdDSAPrivateKey;
use provekit_common::{InputMap, InputValue};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
    rp::RpId,
};
use world_id_test_utils::merkle::first_leaf_merkle_path;

use crate::{
    NoirCircuitInput as _,
    authenticator_attestation::{
        AuthenticatorAssertionClaims, AuthenticatorAssertionToken, AuthenticatorMeta, Platform,
        SecLevel, TrustAnchorKeyClaims, TrustAnchorKeyToken, UserPresence,
    },
    circuit_inputs::{AttestationProofCircuitInput, OwnershipProofCircuitInput},
};

/// Builds static WIP-103 Ownership Proof fixture.
///
/// # Panics
/// Panics if the fixture cannot be built, not expected.
pub(crate) fn ownership_proof_fixture() -> OwnershipProofCircuitInput<TREE_DEPTH> {
    const LEAF_INDEX: u64 = 1;

    let sk = EdDSAPrivateKey::from_bytes([42u8; 32]);
    let key_set = AuthenticatorPublicKeySet::new(vec![sk.public()]).unwrap();
    let (siblings, root) = first_leaf_merkle_path(key_set.leaf_hash());

    let nonce = FieldElement::from(1_234_567_890u64); // <- this is an example, DO NOT use guessable nonces (see spec)
    let context = FieldElement::from(42u64);
    let commitment_blinder = FieldElement::from(999u64);
    let expected_commitment = Credential::compute_sub(LEAF_INDEX, commitment_blinder);
    let message = poseidon::hash(ds::OWNERSHIP_PROOF, [expected_commitment, nonce, context]);

    OwnershipProofCircuitInput {
        key_index: 0,
        key_set,
        inclusion_proof: MerkleInclusionProof::new(root, LEAF_INDEX, siblings),
        nonce,
        expected_commitment,
        context,
        signature: sk.sign(*message),
        commitment_blinder,
    }
}

/// Builds the static WIP-106 Attestation Proof fixture.
///
/// Keys and claims match the known-answer tests in
/// `authenticator_attestation::tests`, and `now` matches `TEST_NOW` in the
/// Noir library's `takt.nr`. Both signatures are deterministic (EdDSA and
/// RFC 6979 ECDSA), so the fixture is stable across runs.
///
/// # Panics
/// Panics if the fixture cannot be built, not expected.
pub(crate) fn attestation_proof_fixture() -> AttestationProofCircuitInput {
    let trust_anchor_key = EdDSAPrivateKey::from_bytes([7u8; 32]);
    let assertion_secret = p256::SecretKey::from_slice(&[11u8; 32]).unwrap();

    let takt_claims = TrustAnchorKeyClaims {
        exp: 1_783_446_925,
        assertion_key: assertion_secret.public_key(),
        sec_level: SecLevel::SecureElement,
        platform: Platform::Ios,
        build_version: 2006,
        sec_meta: 0b11,
    };
    let takt = TrustAnchorKeyToken::new(takt_claims).unwrap();
    let takt_signature = trust_anchor_key.sign(*takt.message_hash().unwrap());

    let aat_claims = AuthenticatorAssertionClaims {
        aud: RpId::new(1_928_118),
        exp: 1_783_446_925,
        nonce: FieldElement::from(0x11d2_23ce_7b91_ac21_u64), // <- example only, DO NOT use guessable nonces (see spec)
        cdh: FieldElement::from(0x9f2c_1abc_u64),
        authenticator_meta: AuthenticatorMeta {
            user_presence: UserPresence::PresentBiometric,
            provider_bits: 0b01,
        },
    };
    let aat = AuthenticatorAssertionToken::new(aat_claims).unwrap();
    let signed = aat.sign(&assertion_secret).unwrap();
    let aat_signature: [u8; 64] = CoseSign1::from_slice(&signed)
        .unwrap()
        .signature
        .try_into()
        .unwrap();

    AttestationProofCircuitInput {
        trust_anchor_key: trust_anchor_key.public().pk,
        now: 1_783_446_025, // exp - 900, within both lifetime caps
        aat_claims,
        aat_signature,
        takt_claims,
        takt_signature,
    }
}

mod ownership_proof_prover {
    use serde::Serialize;

    use super::*;

    /// Every key the circuit ABI is expected to have, in `BTreeMap` (alphabetical) order. A circuit
    /// input added, removed or renamed without updating the renderer below fails these assertions.
    const TOP_LEVEL_KEYS: [&str; 6] = [
        "context",
        "depth",
        "expected_commitment",
        "inputs",
        "merkle_root",
        "nonce",
    ];
    const PRIVATE_KEYS: [&str; 6] = [
        "commitment_blinder",
        "merkle_proof",
        "pk_index",
        "query_r",
        "query_s",
        "user_pk",
    ];

    const HEADER: &str = "\
# Prover.toml for the Ownership Proof circuit (WIP-103).
#
# GENERATED FILE. Do not edit by hand; regenerate with:
#   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof prover_toml

# Public inputs
";

    #[derive(Serialize)]
    struct ProverToml {
        merkle_root: String,
        depth: String,
        nonce: String,
        expected_commitment: String,
        context: String,
        inputs: PrivateInputs,
    }

    #[derive(Serialize)]
    struct PrivateInputs {
        user_pk: Vec<PublicKey>,
        pk_index: String,
        query_s: String,
        query_r: Vec<String>,
        merkle_proof: MerkleProof,
        commitment_blinder: String,
    }

    #[derive(Serialize)]
    struct PublicKey {
        x: String,
        y: String,
    }

    #[derive(Serialize)]
    struct MerkleProof {
        leaf_index: String,
        siblings: Vec<String>,
    }

    fn fixture_witness() -> InputMap {
        ownership_proof_fixture()
            .into_witness()
            .expect("witness generation succeeds")
    }

    fn decimal(value: &InputValue, path: &str) -> String {
        match value {
            InputValue::Field(element) => element.into_repr().to_string(),
            other => panic!("expected `{path}` to be a field element, got {other:?}"),
        }
    }

    fn field(map: &BTreeMap<String, InputValue>, key: &str) -> String {
        decimal(
            map.get(key)
                .unwrap_or_else(|| panic!("missing field `{key}`")),
            key,
        )
    }

    fn array<'a>(map: &'a BTreeMap<String, InputValue>, key: &str) -> &'a [InputValue] {
        match map.get(key) {
            Some(InputValue::Vec(values)) => values,
            other => panic!("expected `{key}` to be an array, got {other:?}"),
        }
    }

    fn table<'a>(
        map: &'a BTreeMap<String, InputValue>,
        key: &str,
    ) -> &'a BTreeMap<String, InputValue> {
        match map.get(key) {
            Some(InputValue::Struct(fields)) => fields,
            other => panic!("expected `{key}` to be a struct, got {other:?}"),
        }
    }

    fn render(witness: &InputMap) -> String {
        let keys: Vec<&str> = witness.keys().map(String::as_str).collect();
        assert_eq!(
            keys, TOP_LEVEL_KEYS,
            "circuit public inputs changed; update this renderer"
        );
        let inputs = table(witness, "inputs");
        let input_keys: Vec<&str> = inputs.keys().map(String::as_str).collect();
        assert_eq!(
            input_keys, PRIVATE_KEYS,
            "circuit private inputs changed; update this renderer"
        );

        let user_pk = array(inputs, "user_pk")
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let path = format!("user_pk[{index}]");
                let InputValue::Struct(coordinates) = key else {
                    panic!("expected `{path}` to be a struct, got {key:?}");
                };
                PublicKey {
                    x: field(coordinates, "x"),
                    y: field(coordinates, "y"),
                }
            })
            .collect();
        let query_r = array(inputs, "query_r")
            .iter()
            .enumerate()
            .map(|(index, coordinate)| decimal(coordinate, &format!("query_r[{index}]")))
            .collect();

        let merkle_proof = table(inputs, "merkle_proof");
        let siblings = array(merkle_proof, "siblings")
            .iter()
            .enumerate()
            .map(|(index, sibling)| decimal(sibling, &format!("siblings[{index}]")))
            .collect();

        let prover_toml = ProverToml {
            merkle_root: field(witness, "merkle_root"),
            depth: field(witness, "depth"),
            nonce: field(witness, "nonce"),
            expected_commitment: field(witness, "expected_commitment"),
            context: field(witness, "context"),
            inputs: PrivateInputs {
                user_pk,
                pk_index: field(inputs, "pk_index"),
                query_s: field(inputs, "query_s"),
                query_r,
                merkle_proof: MerkleProof {
                    leaf_index: field(merkle_proof, "leaf_index"),
                    siblings,
                },
                commitment_blinder: field(inputs, "commitment_blinder"),
            },
        };

        format!(
            "{HEADER}{}",
            toml::to_string_pretty(&prover_toml).expect("fixture serializes to TOML")
        )
    }

    #[test]
    fn prover_toml_matches_the_circuit_input_fixture() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("noir/ownership-proof/Prover.toml");
        let rendered = render(&fixture_witness());

        if env::var_os("UPDATE_PROVER_TOML").is_some() {
            fs::write(&path, &rendered)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            return;
        }

        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert_eq!(
            committed,
            rendered,
            "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof \
         prover_toml`",
            path.display()
        );
    }
}

mod attestation_proof_prover {
    use serde::Serialize;

    use super::*;

    /// Every key the circuit ABI is expected to have, in `BTreeMap` (alphabetical) order. A circuit
    /// input added, removed or renamed without updating the renderer below fails these assertions.
    const TOP_LEVEL_KEYS: [&str; 10] = [
        "aat",
        "aud",
        "authenticator_meta",
        "cdh",
        "nonce",
        "now",
        "sec_flags",
        "takt",
        "trust_anchor_key_x",
        "trust_anchor_key_y",
    ];
    const AAT_KEYS: [&str; 6] = [
        "aud",
        "authenticator_meta",
        "cdh",
        "exp",
        "nonce",
        "signature",
    ];
    const TAKT_KEYS: [&str; 6] = [
        "assertion_key_x",
        "assertion_key_y",
        "exp",
        "sec_flags",
        "sig_r",
        "sig_s",
    ];

    const HEADER: &str = "\
# Prover.toml for the Attestation Proof reference circuit (WIP-106).
#
# GENERATED FILE. Do not edit by hand; regenerate with:
#   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof prover_toml

# Public inputs
";

    #[derive(Serialize)]
    struct ProverToml {
        trust_anchor_key_x: String,
        trust_anchor_key_y: String,
        now: String,
        aud: String,
        nonce: String,
        cdh: String,
        authenticator_meta: String,
        sec_flags: String,
        aat: Aat,
        takt: Takt,
    }

    #[derive(Serialize)]
    struct Aat {
        aud: String,
        exp: String,
        nonce: String,
        cdh: String,
        authenticator_meta: String,
        signature: Vec<String>,
    }

    #[derive(Serialize)]
    struct Takt {
        exp: String,
        assertion_key_x: Vec<String>,
        assertion_key_y: Vec<String>,
        sec_flags: String,
        sig_s: String,
        sig_r: Vec<String>,
    }

    fn fixture_witness() -> InputMap {
        attestation_proof_fixture()
            .into_witness()
            .expect("witness generation succeeds")
    }

    fn decimal(value: &InputValue, path: &str) -> String {
        match value {
            InputValue::Field(element) => element.into_repr().to_string(),
            other => panic!("expected `{path}` to be a field element, got {other:?}"),
        }
    }

    fn field(map: &BTreeMap<String, InputValue>, key: &str) -> String {
        decimal(
            map.get(key)
                .unwrap_or_else(|| panic!("missing field `{key}`")),
            key,
        )
    }

    fn decimals(map: &BTreeMap<String, InputValue>, key: &str) -> Vec<String> {
        match map.get(key) {
            Some(InputValue::Vec(values)) => values
                .iter()
                .enumerate()
                .map(|(index, value)| decimal(value, &format!("{key}[{index}]")))
                .collect(),
            other => panic!("expected `{key}` to be an array, got {other:?}"),
        }
    }

    fn table<'a>(
        map: &'a BTreeMap<String, InputValue>,
        key: &str,
    ) -> &'a BTreeMap<String, InputValue> {
        match map.get(key) {
            Some(InputValue::Struct(fields)) => fields,
            other => panic!("expected `{key}` to be a struct, got {other:?}"),
        }
    }

    fn render(witness: &InputMap) -> String {
        let keys: Vec<&str> = witness.keys().map(String::as_str).collect();
        assert_eq!(
            keys, TOP_LEVEL_KEYS,
            "circuit inputs changed; update this renderer"
        );
        let aat = table(witness, "aat");
        let aat_keys: Vec<&str> = aat.keys().map(String::as_str).collect();
        assert_eq!(
            aat_keys, AAT_KEYS,
            "AAT struct fields changed; update this renderer"
        );
        let takt = table(witness, "takt");
        let takt_keys: Vec<&str> = takt.keys().map(String::as_str).collect();
        assert_eq!(
            takt_keys, TAKT_KEYS,
            "TAKT struct fields changed; update this renderer"
        );

        let prover_toml = ProverToml {
            trust_anchor_key_x: field(witness, "trust_anchor_key_x"),
            trust_anchor_key_y: field(witness, "trust_anchor_key_y"),
            now: field(witness, "now"),
            aud: field(witness, "aud"),
            nonce: field(witness, "nonce"),
            cdh: field(witness, "cdh"),
            authenticator_meta: field(witness, "authenticator_meta"),
            sec_flags: field(witness, "sec_flags"),
            aat: Aat {
                aud: field(aat, "aud"),
                exp: field(aat, "exp"),
                nonce: field(aat, "nonce"),
                cdh: field(aat, "cdh"),
                authenticator_meta: field(aat, "authenticator_meta"),
                signature: decimals(aat, "signature"),
            },
            takt: Takt {
                exp: field(takt, "exp"),
                assertion_key_x: decimals(takt, "assertion_key_x"),
                assertion_key_y: decimals(takt, "assertion_key_y"),
                sec_flags: field(takt, "sec_flags"),
                sig_s: field(takt, "sig_s"),
                sig_r: decimals(takt, "sig_r"),
            },
        };

        format!(
            "{HEADER}{}",
            toml::to_string_pretty(&prover_toml).expect("fixture serializes to TOML")
        )
    }

    #[test]
    fn prover_toml_matches_the_circuit_input_fixture() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("noir/attestation-proof/Prover.toml");
        let rendered = render(&fixture_witness());

        if env::var_os("UPDATE_PROVER_TOML").is_some() {
            fs::write(&path, &rendered)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            return;
        }

        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert_eq!(
            committed,
            rendered,
            "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof \
         prover_toml`",
            path.display()
        );
    }
}
