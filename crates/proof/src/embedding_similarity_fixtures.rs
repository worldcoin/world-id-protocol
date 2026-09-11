//! Fixture generator for the WIP-111 Embedding Similarity circuit
//! (`noir/embedding-similarity`): one coherent witness spanning the registry,
//! the Credential, the WIP-110 Verifier token, and the WIP-106 attestation
//! chain, plus the signed variants the Noir negative tests need.
//!
//! It emits two artifacts: `Prover.toml` (executed by CI with
//! `nargo execute --pedantic-solving`) and `src/test_fixtures.nr` (a flat list
//! of value globals the Noir tests assemble into witnesses). Regenerate both
//! with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity`.

use std::{env, fs, path::PathBuf};

use ark_ff::PrimeField;
use coset::{CborSerializable, CoseSign1};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, DomainSeparator, FieldElement,
    VariableLengthDomainSeparator,
    poseidon::{self, ds},
    rp::RpId,
    sponge::hash_bytes_to_field_element,
};
use world_id_test_utils::merkle::first_leaf_merkle_path;

use crate::authenticator_attestation::{
    AuthenticatorAssertionClaims, AuthenticatorAssertionToken, AuthenticatorMeta, Platform,
    SecLevel, TrustAnchorKeyClaims, TrustAnchorKeyToken, UserPresence,
};

/// Domain separator of the authenticator authorization message (WIP-111 §3.1).
const DS_WIP_111: DomainSeparator<3> = DomainSeparator::new(b"WORLD-ID/WIP-111/SIGN");
/// Domain separator of the WIP-110 Verifier token digest (WIP-110 §3.5.2).
const DS_EVT_V1: DomainSeparator<6> = DomainSeparator::new(b"WORLD_ID_EVT_V1");
/// Domain separator pinning the live item commitment (WIP-111 §3.4).
const DS_LIVE: VariableLengthDomainSeparator =
    VariableLengthDomainSeparator::new(b"WORLD-ID/WIP-111/LIVE");
/// Domain separator pinning the challenge item commitment (WIP-111 §3.4).
const DS_CHALLENGE: VariableLengthDomainSeparator =
    VariableLengthDomainSeparator::new(b"WORLD-ID/WIP-111/CHALLENGE");

const LEAF_INDEX: u64 = 1;
const RP_ID: u64 = 1_928_118;
const NOW: u64 = 1_700_000_000;
const IAT: u64 = NOW - 60;
const SIMILARITY_LIVE: u64 = 9_000;
const SIMILARITY_CHALLENGE: u64 = 8_000;
/// 40_000 seconds after `NOW`: below the 43_200s WIP-111 lifetime ceiling.
const AAT_EXP: u64 = NOW + 40_000;
/// One second past the WIP-111 AAT lifetime ceiling, for the rejection test.
const AAT_EXP_TOO_LONG: u64 = NOW + 43_201;
const TAKT_EXP: u64 = 1_783_446_925;
const GENESIS_ISSUED_AT: u64 = 1_600_000_000;
const EXPIRES_AT: u64 = 1_800_000_000;
const ISSUER_SCHEMA_ID: u64 = 4_242;
const ISSUER_VERSION: u8 = 1;
const CRED_ID: u64 = 7;
const CLAIM_INDEX: usize = 2;
/// `sec_flags`: platform iOS (2), sec_level SecureElement (1), build 2006, sec_meta 3.
const SEC_FLAGS: u64 = 0x0003_0000_07D6_0102;

fn dec(element: impl Into<ark_babyjubjub::Fq>) -> String {
    element.into().into_bigint().to_string()
}

/// Renders bytes as `[1, 2, 3]`: a valid array literal in both Noir and TOML.
fn byte_array(bytes: &[u8]) -> String {
    let list = bytes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{list}]")
}

/// `(s, [r.x, r.y], ["r.x", "r.y"])`: the signature scalar plus its point in
/// Noir and TOML array syntax.
fn sig(signature: &EdDSASignature) -> (String, String, String) {
    let (x, y) = (dec(signature.r.x), dec(signature.r.y));
    (
        signature.s.into_bigint().to_string(),
        format!("[{x}, {y}]"),
        format!("[\"{x}\", \"{y}\"]"),
    )
}

fn noir_point(pk: &EdDSAPublicKey) -> String {
    format!("PublicKey {{ x: {}, y: {} }}", dec(pk.pk.x), dec(pk.pk.y))
}

fn toml_point(pk: &EdDSAPublicKey) -> String {
    format!("x = \"{}\"\ny = \"{}\"", dec(pk.pk.x), dec(pk.pk.y))
}

fn verifier_token_signature(
    verifier_sk: &EdDSAPrivateKey,
    iat: u64,
    commitments: [FieldElement; 3],
    similarity_challenge: u64,
) -> EdDSASignature {
    let [credential, live, challenge] = commitments;
    let digest = poseidon::hash(
        DS_EVT_V1,
        [
            FieldElement::from(iat),
            credential,
            live,
            challenge,
            FieldElement::from(SIMILARITY_LIVE),
            FieldElement::from(similarity_challenge),
        ],
    );
    verifier_sk.sign(*digest)
}

/// Signs an AAT over the fixture claims with the deterministic assertion key,
/// returning the 64-byte `ES256` signature.
fn aat_signature(
    exp: u64,
    nonce: FieldElement,
    live_commitment: FieldElement,
    takt: &[u8],
    assertion_sk: &p256::SecretKey,
) -> [u8; 64] {
    let claims = AuthenticatorAssertionClaims {
        aud: RpId::new(RP_ID),
        exp,
        nonce,
        signal: live_commitment,
        authenticator_meta: AuthenticatorMeta {
            user_presence: UserPresence::PresentBiometric,
            provider_bits: 0b01,
        },
    };
    let token = AuthenticatorAssertionToken::new(claims, takt.to_vec()).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(assertion_sk).unwrap()).unwrap();
    sign1.signature.try_into().unwrap()
}

/// Computes the full witness and renders `(Prover.toml, test_fixtures.nr)`.
#[expect(clippy::too_many_lines)]
fn render() -> (String, String) {
    // Deterministic test keys (not real key material). The authenticator key
    // matches the WIP-103 ownership fixture; the trust anchor and assertion
    // keys match the WIP-106 attestation fixtures.
    let authenticator_sk = EdDSAPrivateKey::from_bytes([42_u8; 32]);
    let issuer_sk = EdDSAPrivateKey::from_bytes([13_u8; 32]);
    let verifier_sk = EdDSAPrivateKey::from_bytes([21_u8; 32]);
    let trust_anchor_sk = EdDSAPrivateKey::from_bytes([7_u8; 32]);
    let assertion_sk = p256::SecretKey::from_slice(&[11_u8; 32]).unwrap();

    let key_set = AuthenticatorPublicKeySet::new(vec![authenticator_sk.public()]).unwrap();
    let (siblings, merkle_root) = first_leaf_merkle_path(key_set.leaf_hash());

    // Commitments over the items each party vouches for (WIP-111 §3.4).
    let credential_commitment =
        hash_bytes_to_field_element(ds::CLAIMS_HASH_V1, b"credential embedding").unwrap();
    let live_commitment = hash_bytes_to_field_element(DS_LIVE, b"live capture").unwrap();
    let challenge_commitment =
        hash_bytes_to_field_element(DS_CHALLENGE, b"challenge frame").unwrap();
    let commitments = [credential_commitment, live_commitment, challenge_commitment];

    let nonce = FieldElement::from(0x11d2_23ce_7b91_ac21_u64);
    let authorization = authenticator_sk.sign(*poseidon::hash(
        DS_WIP_111,
        [live_commitment, nonce, FieldElement::from(RP_ID)],
    ));

    let sub_blinding_factor = FieldElement::from(777_u64);
    let credential = Credential::new()
        .id(CRED_ID)
        .issuer_version(ISSUER_VERSION)
        .issuer_schema_id(ISSUER_SCHEMA_ID)
        .subject(Credential::compute_sub(LEAF_INDEX, sub_blinding_factor))
        .genesis_issued_at(GENESIS_ISSUED_AT)
        .expires_at(EXPIRES_AT)
        .claim_hash(
            CLAIM_INDEX,
            ruint::aliases::U256::from_be_bytes(credential_commitment.to_be_bytes()),
        )
        .unwrap()
        .sign(&issuer_sk)
        .unwrap();
    // An otherwise identical credential already expired at `NOW`, for the
    // validity-window rejection test (`now < expires_at` fails on equality).
    let expired_signature = {
        let mut expired = credential.clone();
        expired.expires_at = NOW;
        expired.sign(&issuer_sk).unwrap().signature.unwrap()
    };

    let session_id_r = FieldElement::from(555_u64);
    let session_id = poseidon::hash(
        ds::SESSION_COMMITMENT,
        [FieldElement::from(LEAF_INDEX), session_id_r],
    );

    let cwt = verifier_token_signature(&verifier_sk, IAT, commitments, SIMILARITY_CHALLENGE);
    // 2-way flow: nil challenge commitment, nil challenge score.
    let cwt_two_way = verifier_token_signature(
        &verifier_sk,
        IAT,
        [credential_commitment, live_commitment, FieldElement::ZERO],
        0,
    );
    // Future-dated token: `iat > now` must be rejected even when fresh-looking.
    let cwt_future_iat =
        verifier_token_signature(&verifier_sk, NOW + 10, commitments, SIMILARITY_CHALLENGE);

    let takt = TrustAnchorKeyToken::new(TrustAnchorKeyClaims {
        exp: TAKT_EXP,
        assertion_key: assertion_sk.public_key(),
        sec_level: SecLevel::SecureElement,
        platform: Platform::Ios,
        build_version: 2006,
        sec_meta: 0b11,
    })
    .unwrap()
    .sign(&trust_anchor_sk)
    .unwrap();
    let takt_sig = EdDSASignature::from_compressed_bytes(
        CoseSign1::from_slice(&takt)
            .unwrap()
            .signature
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let assertion_point = assertion_sk.public_key().to_encoded_point(false);
    let assertion_key_x = byte_array(assertion_point.x().unwrap());
    let assertion_key_y = byte_array(assertion_point.y().unwrap());
    let aat_sig = byte_array(&aat_signature(
        AAT_EXP,
        nonce,
        live_commitment,
        &takt,
        &assertion_sk,
    ));
    let aat_sig_too_long = byte_array(&aat_signature(
        AAT_EXP_TOO_LONG,
        nonce,
        live_commitment,
        &takt,
        &assertion_sk,
    ));

    let (auth_s, auth_r, auth_r_toml) = sig(&authorization);
    let (cred_s, cred_r, cred_r_toml) = sig(credential.signature.as_ref().unwrap());
    let (cred_exp_s, cred_exp_r, _) = sig(&expired_signature);
    let (cwt_s, cwt_r, cwt_r_toml) = sig(&cwt);
    let (cwt2_s, cwt2_r, _) = sig(&cwt_two_way);
    let (cwtf_s, cwtf_r, _) = sig(&cwt_future_iat);
    let (takt_s, takt_r, takt_r_toml) = sig(&takt_sig);

    // The Noir globals: `(name, type, value)`, one `pub global` each. Recipe
    // scalars and computed values alike live here so the Noir tests share one
    // source of truth with `Prover.toml`. Values Noir can recompute (siblings,
    // merkle root, session commitment, the claims array) are not emitted.
    #[rustfmt::skip]
    let globals: Vec<(&str, &str, String)> = vec![
        // Public inputs
        ("TRUST_ANCHOR_KEY", "PublicKey", noir_point(&trust_anchor_sk.public())),
        ("AUTHENTICATOR_META", "Field", "10".into()),
        ("NONCE", "Field", dec(*nonce)),
        ("RP_ID", "Field", RP_ID.to_string()),
        ("NOW", "Field", NOW.to_string()),
        ("GENESIS_ISSUED_AT_MIN", "Field", "1500000000".into()),
        ("VERIFIER_KEY", "PublicKey", noir_point(&verifier_sk.public())),
        ("CHALLENGE_COMMITMENT", "Field", dec(*challenge_commitment)),
        ("COMPARISON_AGE_MAX", "Field", "300".into()),
        ("SIMILARITY_MIN", "Field", "5000".into()),
        ("ISSUER_SCHEMA_ID", "Field", ISSUER_SCHEMA_ID.to_string()),
        ("CRED_PK", "PublicKey", noir_point(&credential.issuer)),
        ("ISSUER_VERSION", "Field", ISSUER_VERSION.to_string()),
        ("CLAIM_INDEX", "Field", CLAIM_INDEX.to_string()),
        // Expected public outputs
        ("SEC_LEVEL", "Field", (SecLevel::SecureElement as u64).to_string()),
        ("SEC_META", "Field", "3".into()),
        // Registry witness
        ("USER_PK", "PublicKey", noir_point(&authenticator_sk.public())),
        ("AUTH_SIG_S", "Field", auth_s.clone()),
        ("AUTH_SIG_R", "[Field; 2]", auth_r),
        ("LEAF_INDEX", "Field", LEAF_INDEX.to_string()),
        // Credential witness (claims are all zero except `claims[CLAIM_INDEX]`)
        ("GENESIS_ISSUED_AT", "Field", GENESIS_ISSUED_AT.to_string()),
        ("EXPIRES_AT", "Field", EXPIRES_AT.to_string()),
        ("SUB_BLINDING_FACTOR", "Field", dec(*sub_blinding_factor)),
        ("CRED_ID", "Field", CRED_ID.to_string()),
        ("CRED_SIG_S", "Field", cred_s.clone()),
        ("CRED_SIG_R", "[Field; 2]", cred_r.clone()),
        // Verifier token witness
        ("IAT", "Field", IAT.to_string()),
        ("CREDENTIAL_COMMITMENT", "Field", dec(*credential_commitment)),
        ("LIVE_COMMITMENT", "Field", dec(*live_commitment)),
        ("SIMILARITY_LIVE", "Field", SIMILARITY_LIVE.to_string()),
        ("SIMILARITY_CHALLENGE", "Field", SIMILARITY_CHALLENGE.to_string()),
        ("CWT_SIG_S", "Field", cwt_s.clone()),
        ("CWT_SIG_R", "[Field; 2]", cwt_r.clone()),
        // Attestation chain witness
        ("TAKT_EXP", "Field", TAKT_EXP.to_string()),
        ("ASSERTION_KEY_X", "[u8; 32]", assertion_key_x.clone()),
        ("ASSERTION_KEY_Y", "[u8; 32]", assertion_key_y.clone()),
        ("SEC_FLAGS", "Field", SEC_FLAGS.to_string()),
        ("TAKT_SIG_S", "Field", takt_s.clone()),
        ("TAKT_SIG_R", "[Field; 2]", takt_r.clone()),
        ("AAT_EXP", "Field", AAT_EXP.to_string()),
        ("AAT_SIGNATURE", "[u8; 64]", aat_sig.clone()),
        ("SESSION_ID_R", "Field", dec(*session_id_r)),
        // Signed variants for the negative tests
        ("AAT_EXP_TOO_LONG", "Field", AAT_EXP_TOO_LONG.to_string()),
        ("AAT_SIGNATURE_TOO_LONG_EXP", "[u8; 64]", aat_sig_too_long),
        ("FUTURE_IAT", "Field", (NOW + 10).to_string()),
        ("CWT_SIG_S_TWO_WAY", "Field", cwt2_s),
        ("CWT_SIG_R_TWO_WAY", "[Field; 2]", cwt2_r),
        ("CWT_SIG_S_FUTURE_IAT", "Field", cwtf_s),
        ("CWT_SIG_R_FUTURE_IAT", "[Field; 2]", cwtf_r),
        ("EXPIRED_EXPIRES_AT", "Field", NOW.to_string()),
        ("CRED_SIG_S_EXPIRED", "Field", cred_exp_s),
        ("CRED_SIG_R_EXPIRED", "[Field; 2]", cred_exp_r),
    ];

    let noir = format!(
        "// GENERATED FILE: one coherent WIP-111 witness plus the signed variants the\n\
         // negative tests need, as flat value globals (`tests.nr` assembles them).\n\
         // Regenerate with:\n\
         //   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity\n\
         // Keys derive from constant test seeds (not real key material); values\n\
         // mirror `Prover.toml`.\n\
         use super::types::PublicKey;\n\n{}",
        globals
            .iter()
            .map(|(name, ty, value)| format!("pub global {name}: {ty} = {value};\n"))
            .collect::<String>()
    );

    // Inactive registry slots hold the BabyJubJub identity (0, 1).
    let user_pk = std::iter::once(toml_point(&authenticator_sk.public()))
        .chain(std::iter::repeat_n("x = \"0\"\ny = \"1\"".to_string(), 6))
        .map(|point| format!("\n[[inputs.registry.user_pk]]\n{point}\n"))
        .collect::<String>();
    let mut claims = vec!["\"0\"".to_string(); Credential::MAX_CLAIMS];
    claims[CLAIM_INDEX] = format!("\"{}\"", dec(*credential_commitment));
    let claims = claims.join(", ");
    let siblings = siblings
        .iter()
        .map(|s| format!("\"{}\"", dec(**s)))
        .collect::<Vec<_>>()
        .join(", ");

    let toml = format!(
        "# Prover.toml for the Embedding Similarity circuit (WIP-111).\n\
         #\n\
         # GENERATED FILE. Do not edit by hand; regenerate with:\n\
         #   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity\n\
         \n\
         # Public inputs\n\
         authenticator_meta = \"10\"\n\
         nonce = \"{nonce}\"\n\
         rp_id = \"{RP_ID}\"\n\
         now = \"{NOW}\"\n\
         session_id = \"{session_id}\"\n\
         genesis_issued_at_min = \"1500000000\"\n\
         challenge_commitment = \"{challenge_commitment}\"\n\
         comparison_age_max = \"300\"\n\
         similarity_min = \"5000\"\n\
         merkle_root = \"{merkle_root}\"\n\
         issuer_schema_id = \"{ISSUER_SCHEMA_ID}\"\n\
         issuer_version = \"{ISSUER_VERSION}\"\n\
         claim_index = \"{CLAIM_INDEX}\"\n\
         \n\
         [trust_anchor_key]\n{trust_anchor_key}\n\
         \n\
         [verifier_key]\n{verifier_key}\n\
         \n\
         [cred_pk]\n{cred_pk}\n\
         \n\
         # Private inputs\n\
         [inputs]\n\
         aat_exp = \"{AAT_EXP}\"\n\
         aat_signature = {aat_sig}\n\
         session_id_r = \"{session_id_r}\"\n\
         \n\
         [inputs.registry]\n\
         pk_index = \"0\"\n\
         sig_s = \"{auth_s}\"\n\
         sig_r = {auth_r_toml}\n\
         leaf_index = \"{LEAF_INDEX}\"\n\
         siblings = [{siblings}]\n\
         {user_pk}\
         \n\
         [inputs.credential]\n\
         claims = [{claims}]\n\
         associated_data_hash = \"0\"\n\
         genesis_issued_at = \"{GENESIS_ISSUED_AT}\"\n\
         expires_at = \"{EXPIRES_AT}\"\n\
         sub_blinding_factor = \"{sub_blinding_factor}\"\n\
         id = \"{CRED_ID}\"\n\
         sig_s = \"{cred_s}\"\n\
         sig_r = {cred_r_toml}\n\
         \n\
         [inputs.cwt]\n\
         iat = \"{IAT}\"\n\
         credential_commitment = \"{credential_commitment}\"\n\
         live_commitment = \"{live_commitment}\"\n\
         similarity_live = \"{SIMILARITY_LIVE}\"\n\
         similarity_challenge = \"{SIMILARITY_CHALLENGE}\"\n\
         sig_s = \"{cwt_s}\"\n\
         sig_r = {cwt_r_toml}\n\
         \n\
         [inputs.takt]\n\
         exp = \"{TAKT_EXP}\"\n\
         assertion_key_x = {assertion_key_x}\n\
         assertion_key_y = {assertion_key_y}\n\
         sec_flags = \"{SEC_FLAGS}\"\n\
         sig_s = \"{takt_s}\"\n\
         sig_r = {takt_r_toml}\n",
        nonce = dec(*nonce),
        session_id = dec(*session_id),
        challenge_commitment = dec(*challenge_commitment),
        merkle_root = dec(*merkle_root),
        trust_anchor_key = toml_point(&trust_anchor_sk.public()),
        verifier_key = toml_point(&verifier_sk.public()),
        cred_pk = toml_point(&credential.issuer),
        session_id_r = dec(*session_id_r),
        sub_blinding_factor = dec(*sub_blinding_factor),
        credential_commitment = dec(*credential_commitment),
        live_commitment = dec(*live_commitment),
    );

    (toml, noir)
}

fn noir_package_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("noir/embedding-similarity/{file}"))
}

#[test]
fn prover_toml_matches_the_fixture() {
    let (toml, noir) = render();
    let path = noir_package_path("Prover.toml");

    if env::var_os("UPDATE_PROVER_TOML").is_some() {
        fs::write(&path, &toml)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
        let noir_path = noir_package_path("src/test_fixtures.nr");
        fs::write(&noir_path, noir)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", noir_path.display()));
        return;
    }

    let committed = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    assert_eq!(
        committed,
        toml,
        "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof \
         embedding_similarity` (and re-run `nargo fmt` for src/test_fixtures.nr)",
        path.display()
    );
}

/// Pins the WIP-111/WIP-110 domain separators to the integers hardcoded in the
/// Noir package so the two implementations cannot silently diverge.
#[test]
fn domain_separators_match_the_noir_constants() {
    let as_int = |tag: &[u8]| dec(ark_babyjubjub::Fq::from_be_bytes_mod_order(tag));
    assert_eq!(
        as_int(b"WORLD-ID/WIP-111/SIGN"),
        "127603488023523044162070750169730678246161835968334"
    );
    assert_eq!(
        as_int(b"WORLD_ID_EVT_V1"),
        "453338657364062333832270442605270577"
    );
    assert_eq!(
        as_int(b"POSEIDON2+EDDSA-BJJ"),
        "1790969822004668215611014194230797064349043274"
    );
    assert_eq!(as_int(b"H_CS(id, r)"), "87492525752134038588518953");
    assert_eq!(as_int(b"H(id, r)"), "5199521648757207593");
    assert_eq!(as_int(b"World ID PK"), "105702839725298824521994315");
}
