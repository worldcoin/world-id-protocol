//! Fixture generator for the WIP-111 Embedding Similarity circuit
//! (`noir/embedding-similarity`): one coherent witness spanning the registry,
//! the Credential, the WIP-110 Verifier token, and the WIP-106 attestation
//! chain, plus the signed variants the Noir negative tests need.
//!
//! Regenerate the committed artifacts with:
//! `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity`
//! then run `nargo fmt` in the Noir package (`src/test_fixtures.nr` is written
//! without regard for formatting).

use std::{env, fmt::Write as _, fs, path::PathBuf};

use ark_ff::PrimeField;
use coset::{CborSerializable, CoseSign1};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSASignature};
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
/// 60 seconds before `NOW`.
const IAT: u64 = NOW - 60;
const COMPARISON_AGE_MAX: u64 = 300;
const SIMILARITY_MIN: u64 = 5_000;
const SIMILARITY_LIVE: u64 = 9_000;
const SIMILARITY_CHALLENGE: u64 = 8_000;
/// 40_000 seconds after `NOW`: below the 43_200s WIP-111 lifetime ceiling.
const AAT_EXP: u64 = NOW + 40_000;
/// One second past the WIP-111 AAT lifetime ceiling, for the rejection test.
const AAT_EXP_TOO_LONG: u64 = NOW + 43_201;
const TAKT_EXP: u64 = 1_783_446_925;
const GENESIS_ISSUED_AT: u64 = 1_600_000_000;
const GENESIS_ISSUED_AT_MIN: u64 = 1_500_000_000;
const EXPIRES_AT: u64 = 1_800_000_000;
const ISSUER_SCHEMA_ID: u64 = 4_242;
const ISSUER_VERSION: u8 = 1;
const CRED_ID: u64 = 7;
const CLAIM_INDEX: usize = 2;

/// The one coherent WIP-111 witness the Noir happy-path test and `Prover.toml` share.
struct Fixture {
    key_set: AuthenticatorPublicKeySet,
    siblings: Vec<FieldElement>,
    merkle_root: FieldElement,
    authorization: EdDSASignature,
    credential: Credential,
    sub_blinding_factor: FieldElement,
    nonce: FieldElement,
    session_id_r: FieldElement,
    session_id: FieldElement,
    live_commitment: FieldElement,
    challenge_commitment: FieldElement,
    credential_commitment: FieldElement,
    cwt_signature: EdDSASignature,
    verifier_pk: eddsa_babyjubjub::EdDSAPublicKey,
    trust_anchor_pk: eddsa_babyjubjub::EdDSAPublicKey,
    assertion_key: p256::PublicKey,
    takt_signature: EdDSASignature,
    aat_signature: [u8; 64],
    sec_flags: u64,
    // Signed variants for the Noir negative tests.
    aat_signature_too_long_exp: [u8; 64],
    cwt_signature_two_way: EdDSASignature,
    cwt_signature_future_iat: EdDSASignature,
    credential_expired_signature: EdDSASignature,
}

fn verifier_token_signature(
    verifier_sk: &EdDSAPrivateKey,
    iat: u64,
    credential_commitment: FieldElement,
    live_commitment: FieldElement,
    challenge_commitment: FieldElement,
    similarity_live: u64,
    similarity_challenge: u64,
) -> EdDSASignature {
    let digest = poseidon::hash(
        DS_EVT_V1,
        [
            FieldElement::from(iat),
            credential_commitment,
            live_commitment,
            challenge_commitment,
            FieldElement::from(similarity_live),
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

fn fixture() -> Fixture {
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
        .claim_hash(0, ruint::aliases::U256::from(1_u64))
        .unwrap()
        .claim_hash(
            CLAIM_INDEX,
            ruint::aliases::U256::from_be_bytes(credential_commitment.to_be_bytes()),
        )
        .unwrap()
        .sign(&issuer_sk)
        .unwrap();

    // An otherwise identical credential already expired at `NOW`, for the
    // validity-window rejection test (`now < expires_at` fails on equality).
    let credential_expired_signature = {
        let mut expired = credential.clone();
        expired.expires_at = NOW;
        expired.sign(&issuer_sk).unwrap().signature.unwrap()
    };

    let session_id_r = FieldElement::from(555_u64);
    let session_id = poseidon::hash(
        ds::SESSION_COMMITMENT,
        [FieldElement::from(LEAF_INDEX), session_id_r],
    );

    let cwt_signature = verifier_token_signature(
        &verifier_sk,
        IAT,
        credential_commitment,
        live_commitment,
        challenge_commitment,
        SIMILARITY_LIVE,
        SIMILARITY_CHALLENGE,
    );
    // 2-way flow: nil challenge commitment, nil challenge score.
    let cwt_signature_two_way = verifier_token_signature(
        &verifier_sk,
        IAT,
        credential_commitment,
        live_commitment,
        FieldElement::ZERO,
        SIMILARITY_LIVE,
        0,
    );
    // Future-dated token: `iat > now` must be rejected even when fresh-looking.
    let cwt_signature_future_iat = verifier_token_signature(
        &verifier_sk,
        NOW + 10,
        credential_commitment,
        live_commitment,
        challenge_commitment,
        SIMILARITY_LIVE,
        SIMILARITY_CHALLENGE,
    );

    let takt_claims = TrustAnchorKeyClaims {
        exp: TAKT_EXP,
        assertion_key: assertion_sk.public_key(),
        sec_level: SecLevel::SecureElement,
        platform: Platform::Ios,
        build_version: 2006,
        sec_meta: 0b11,
    };
    let takt = TrustAnchorKeyToken::new(takt_claims)
        .unwrap()
        .sign(&trust_anchor_sk)
        .unwrap();
    let takt_sign1 = CoseSign1::from_slice(&takt).unwrap();
    let takt_signature =
        EdDSASignature::from_compressed_bytes(takt_sign1.signature.clone().try_into().unwrap())
            .unwrap();

    Fixture {
        key_set,
        siblings: siblings.to_vec(),
        merkle_root,
        authorization,
        credential,
        sub_blinding_factor,
        nonce,
        session_id_r,
        session_id,
        live_commitment,
        challenge_commitment,
        credential_commitment,
        cwt_signature,
        verifier_pk: verifier_sk.public(),
        trust_anchor_pk: trust_anchor_sk.public(),
        assertion_key: assertion_sk.public_key(),
        takt_signature,
        aat_signature: aat_signature(AAT_EXP, nonce, live_commitment, &takt, &assertion_sk),
        sec_flags: (Platform::Ios as u64)
            | ((SecLevel::SecureElement as u64) << 8)
            | (2006_u64 << 16)
            | (0b11_u64 << 48),
        aat_signature_too_long_exp: aat_signature(
            AAT_EXP_TOO_LONG,
            nonce,
            live_commitment,
            &takt,
            &assertion_sk,
        ),
        cwt_signature_two_way,
        cwt_signature_future_iat,
        credential_expired_signature,
    }
}

fn dec(element: FieldElement) -> String {
    element.into_bigint().to_string()
}

fn dec_fq(element: ark_babyjubjub::Fq) -> String {
    element.into_bigint().to_string()
}

/// Renders an EdDSA signature as `(s, [r.x, r.y])` decimal strings.
fn signature_parts(signature: &EdDSASignature) -> (String, String, String) {
    (
        signature.s.into_bigint().to_string(),
        dec_fq(signature.r.x),
        dec_fq(signature.r.y),
    )
}

fn byte_list(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn quoted_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn user_pk_entries(fixture: &Fixture) -> Vec<(String, String)> {
    fixture
        .key_set
        .as_affine_array()
        .iter()
        .map(|pk| (dec_fq(pk.x), dec_fq(pk.y)))
        .collect()
}

fn render_prover_toml(fixture: &Fixture) -> String {
    let (auth_s, auth_rx, auth_ry) = signature_parts(&fixture.authorization);
    let cred_signature = fixture.credential.signature.as_ref().unwrap();
    let (cred_s, cred_rx, cred_ry) = signature_parts(cred_signature);
    let (cwt_s, cwt_rx, cwt_ry) = signature_parts(&fixture.cwt_signature);
    let (takt_s, takt_rx, takt_ry) = signature_parts(&fixture.takt_signature);
    let assertion_point = fixture.assertion_key.to_encoded_point(false);

    let mut out = String::from(
        "# Prover.toml for the Embedding Similarity circuit (WIP-111).\n#\n\
         # GENERATED FILE. Do not edit by hand; regenerate with:\n\
         #   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity\n\n\
         # Public inputs\n",
    );
    let claims: Vec<String> = fixture.credential.claims.iter().map(|c| dec(*c)).collect();
    let siblings: Vec<String> = fixture.siblings.iter().map(|s| dec(*s)).collect();

    writeln!(out, "authenticator_meta = \"10\"").unwrap();
    writeln!(out, "nonce = \"{}\"", dec(fixture.nonce)).unwrap();
    writeln!(out, "rp_id = \"{RP_ID}\"").unwrap();
    writeln!(out, "now = \"{NOW}\"").unwrap();
    writeln!(out, "session_id = \"{}\"", dec(fixture.session_id)).unwrap();
    writeln!(out, "genesis_issued_at_min = \"{GENESIS_ISSUED_AT_MIN}\"").unwrap();
    writeln!(
        out,
        "challenge_commitment = \"{}\"",
        dec(fixture.challenge_commitment)
    )
    .unwrap();
    writeln!(out, "comparison_age_max = \"{COMPARISON_AGE_MAX}\"").unwrap();
    writeln!(out, "similarity_min = \"{SIMILARITY_MIN}\"").unwrap();
    writeln!(out, "merkle_root = \"{}\"", dec(fixture.merkle_root)).unwrap();
    writeln!(out, "issuer_schema_id = \"{ISSUER_SCHEMA_ID}\"").unwrap();
    writeln!(out, "issuer_version = \"{ISSUER_VERSION}\"").unwrap();
    writeln!(out, "claim_index = \"{CLAIM_INDEX}\"").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[trust_anchor_key]").unwrap();
    writeln!(out, "x = \"{}\"", dec_fq(fixture.trust_anchor_pk.pk.x)).unwrap();
    writeln!(out, "y = \"{}\"", dec_fq(fixture.trust_anchor_pk.pk.y)).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[verifier_key]").unwrap();
    writeln!(out, "x = \"{}\"", dec_fq(fixture.verifier_pk.pk.x)).unwrap();
    writeln!(out, "y = \"{}\"", dec_fq(fixture.verifier_pk.pk.y)).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[cred_pk]").unwrap();
    let issuer_pk = fixture.credential.issuer.pk;
    writeln!(out, "x = \"{}\"", dec_fq(issuer_pk.x)).unwrap();
    writeln!(out, "y = \"{}\"", dec_fq(issuer_pk.y)).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "# Private inputs").unwrap();
    writeln!(out, "[inputs]").unwrap();
    writeln!(out, "aat_exp = \"{AAT_EXP}\"").unwrap();
    writeln!(
        out,
        "aat_signature = [{}]",
        byte_list(&fixture.aat_signature)
    )
    .unwrap();
    writeln!(out, "session_id_r = \"{}\"", dec(fixture.session_id_r)).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[inputs.registry]").unwrap();
    writeln!(out, "pk_index = \"0\"").unwrap();
    writeln!(out, "sig_s = \"{auth_s}\"").unwrap();
    writeln!(out, "sig_r = [\"{auth_rx}\", \"{auth_ry}\"]").unwrap();
    writeln!(out, "leaf_index = \"{LEAF_INDEX}\"").unwrap();
    writeln!(out, "siblings = [{}]", quoted_list(&siblings)).unwrap();
    for (x, y) in user_pk_entries(fixture) {
        writeln!(out).unwrap();
        writeln!(out, "[[inputs.registry.user_pk]]").unwrap();
        writeln!(out, "x = \"{x}\"").unwrap();
        writeln!(out, "y = \"{y}\"").unwrap();
    }
    writeln!(out).unwrap();
    writeln!(out, "[inputs.credential]").unwrap();
    writeln!(out, "claims = [{}]", quoted_list(&claims)).unwrap();
    writeln!(out, "associated_data_hash = \"0\"").unwrap();
    writeln!(out, "genesis_issued_at = \"{GENESIS_ISSUED_AT}\"").unwrap();
    writeln!(out, "expires_at = \"{EXPIRES_AT}\"").unwrap();
    writeln!(
        out,
        "sub_blinding_factor = \"{}\"",
        dec(fixture.sub_blinding_factor)
    )
    .unwrap();
    writeln!(out, "id = \"{CRED_ID}\"").unwrap();
    writeln!(out, "sig_s = \"{cred_s}\"").unwrap();
    writeln!(out, "sig_r = [\"{cred_rx}\", \"{cred_ry}\"]").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[inputs.cwt]").unwrap();
    writeln!(out, "iat = \"{IAT}\"").unwrap();
    writeln!(
        out,
        "credential_commitment = \"{}\"",
        dec(fixture.credential_commitment)
    )
    .unwrap();
    writeln!(
        out,
        "live_commitment = \"{}\"",
        dec(fixture.live_commitment)
    )
    .unwrap();
    writeln!(out, "similarity_live = \"{SIMILARITY_LIVE}\"").unwrap();
    writeln!(out, "similarity_challenge = \"{SIMILARITY_CHALLENGE}\"").unwrap();
    writeln!(out, "sig_s = \"{cwt_s}\"").unwrap();
    writeln!(out, "sig_r = [\"{cwt_rx}\", \"{cwt_ry}\"]").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[inputs.takt]").unwrap();
    writeln!(out, "exp = \"{TAKT_EXP}\"").unwrap();
    writeln!(
        out,
        "assertion_key_x = [{}]",
        byte_list(assertion_point.x().unwrap())
    )
    .unwrap();
    writeln!(
        out,
        "assertion_key_y = [{}]",
        byte_list(assertion_point.y().unwrap())
    )
    .unwrap();
    writeln!(out, "sec_flags = \"{}\"", fixture.sec_flags).unwrap();
    writeln!(out, "sig_s = \"{takt_s}\"").unwrap();
    writeln!(out, "sig_r = [\"{takt_rx}\", \"{takt_ry}\"]").unwrap();

    out
}

fn render_noir_fixtures(fixture: &Fixture) -> String {
    let (auth_s, auth_rx, auth_ry) = signature_parts(&fixture.authorization);
    let cred_signature = fixture.credential.signature.as_ref().unwrap();
    let (cred_s, cred_rx, cred_ry) = signature_parts(cred_signature);
    let (cwt_s, cwt_rx, cwt_ry) = signature_parts(&fixture.cwt_signature);
    let (cwt2_s, cwt2_rx, cwt2_ry) = signature_parts(&fixture.cwt_signature_two_way);
    let (cwtf_s, cwtf_rx, cwtf_ry) = signature_parts(&fixture.cwt_signature_future_iat);
    let (takt_s, takt_rx, takt_ry) = signature_parts(&fixture.takt_signature);
    let assertion_point = fixture.assertion_key.to_encoded_point(false);
    let claims: Vec<String> = fixture.credential.claims.iter().map(|c| dec(*c)).collect();
    let siblings: Vec<String> = fixture.siblings.iter().map(|s| dec(*s)).collect();
    let user_pk: Vec<String> = user_pk_entries(fixture)
        .iter()
        .map(|(x, y)| format!("PublicKey {{ x: {x}, y: {y} }}"))
        .collect();

    let mut out = String::from(
        "// GENERATED FILE covering one coherent WIP-111 witness plus the signed\n\
         // variants the negative tests need. Regenerate with:\n\
         //   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity\n\
         // then re-run `nargo fmt`. Keys derive from constant test seeds (not real\n\
         // key material); values mirror `Prover.toml`.\n\
         use super::types::{\n\
         \x20   CredentialInputs, PrivateInputs, PublicKey, RegistryInputs, TaktInputs,\n\
         \x20   VerifierTokenInputs,\n\
         };\n\n",
    );

    let mut global = |name: &str, ty: &str, value: &str| {
        writeln!(out, "pub global {name}: {ty} = {value};").unwrap();
    };

    global("AUTHENTICATOR_META", "Field", "10");
    global("NONCE", "Field", &dec(fixture.nonce));
    global("RP_ID", "Field", &RP_ID.to_string());
    global("NOW", "Field", &NOW.to_string());
    global("SESSION_ID", "Field", &dec(fixture.session_id));
    global(
        "GENESIS_ISSUED_AT_MIN",
        "Field",
        &GENESIS_ISSUED_AT_MIN.to_string(),
    );
    global(
        "CHALLENGE_COMMITMENT",
        "Field",
        &dec(fixture.challenge_commitment),
    );
    global(
        "COMPARISON_AGE_MAX",
        "Field",
        &COMPARISON_AGE_MAX.to_string(),
    );
    global("SIMILARITY_MIN", "Field", &SIMILARITY_MIN.to_string());
    global("MERKLE_ROOT", "Field", &dec(fixture.merkle_root));
    global("ISSUER_SCHEMA_ID", "Field", &ISSUER_SCHEMA_ID.to_string());
    global("ISSUER_VERSION", "Field", &ISSUER_VERSION.to_string());
    global("CLAIM_INDEX", "Field", &CLAIM_INDEX.to_string());
    global(
        "TRUST_ANCHOR_KEY",
        "PublicKey",
        &format!(
            "PublicKey {{ x: {}, y: {} }}",
            dec_fq(fixture.trust_anchor_pk.pk.x),
            dec_fq(fixture.trust_anchor_pk.pk.y)
        ),
    );
    global(
        "VERIFIER_KEY",
        "PublicKey",
        &format!(
            "PublicKey {{ x: {}, y: {} }}",
            dec_fq(fixture.verifier_pk.pk.x),
            dec_fq(fixture.verifier_pk.pk.y)
        ),
    );
    global(
        "CRED_PK",
        "PublicKey",
        &format!(
            "PublicKey {{ x: {}, y: {} }}",
            dec_fq(fixture.credential.issuer.pk.x),
            dec_fq(fixture.credential.issuer.pk.y)
        ),
    );
    global(
        "SEC_LEVEL",
        "Field",
        &(SecLevel::SecureElement as u64).to_string(),
    );
    global("SEC_META", "Field", "3");
    global("AAT_EXP_TOO_LONG", "Field", &AAT_EXP_TOO_LONG.to_string());
    global(
        "AAT_SIGNATURE_TOO_LONG_EXP",
        "[u8; 64]",
        &format!("[{}]", byte_list(&fixture.aat_signature_too_long_exp)),
    );
    global("FUTURE_IAT", "Field", &(NOW + 10).to_string());
    global("CWT_SIG_S_TWO_WAY", "Field", &cwt2_s);
    global(
        "CWT_SIG_R_TWO_WAY",
        "[Field; 2]",
        &format!("[{cwt2_rx}, {cwt2_ry}]"),
    );
    global("CWT_SIG_S_FUTURE_IAT", "Field", &cwtf_s);
    global(
        "CWT_SIG_R_FUTURE_IAT",
        "[Field; 2]",
        &format!("[{cwtf_rx}, {cwtf_ry}]"),
    );
    let (cred_exp_s, cred_exp_rx, cred_exp_ry) =
        signature_parts(&fixture.credential_expired_signature);
    global("EXPIRED_EXPIRES_AT", "Field", &NOW.to_string());
    global("CRED_SIG_S_EXPIRED", "Field", &cred_exp_s);
    global(
        "CRED_SIG_R_EXPIRED",
        "[Field; 2]",
        &format!("[{cred_exp_rx}, {cred_exp_ry}]"),
    );

    writeln!(
        out,
        "\npub fn fixture_inputs() -> PrivateInputs {{\n\
         \x20   PrivateInputs {{\n\
         \x20       registry: RegistryInputs {{\n\
         \x20           user_pk: [{user_pk}],\n\
         \x20           pk_index: 0,\n\
         \x20           sig_s: {auth_s},\n\
         \x20           sig_r: [{auth_rx}, {auth_ry}],\n\
         \x20           leaf_index: {LEAF_INDEX},\n\
         \x20           siblings: [{siblings}],\n\
         \x20       }},\n\
         \x20       credential: CredentialInputs {{\n\
         \x20           claims: [{claims}],\n\
         \x20           associated_data_hash: 0,\n\
         \x20           genesis_issued_at: {GENESIS_ISSUED_AT},\n\
         \x20           expires_at: {EXPIRES_AT},\n\
         \x20           sub_blinding_factor: {sub_blinding_factor},\n\
         \x20           id: {CRED_ID},\n\
         \x20           sig_s: {cred_s},\n\
         \x20           sig_r: [{cred_rx}, {cred_ry}],\n\
         \x20       }},\n\
         \x20       cwt: VerifierTokenInputs {{\n\
         \x20           iat: {IAT},\n\
         \x20           credential_commitment: {credential_commitment},\n\
         \x20           live_commitment: {live_commitment},\n\
         \x20           similarity_live: {SIMILARITY_LIVE},\n\
         \x20           similarity_challenge: {SIMILARITY_CHALLENGE},\n\
         \x20           sig_s: {cwt_s},\n\
         \x20           sig_r: [{cwt_rx}, {cwt_ry}],\n\
         \x20       }},\n\
         \x20       takt: TaktInputs {{\n\
         \x20           exp: {TAKT_EXP},\n\
         \x20           assertion_key_x: [{assertion_x}],\n\
         \x20           assertion_key_y: [{assertion_y}],\n\
         \x20           sec_flags: {sec_flags},\n\
         \x20           sig_s: {takt_s},\n\
         \x20           sig_r: [{takt_rx}, {takt_ry}],\n\
         \x20       }},\n\
         \x20       aat_exp: {AAT_EXP},\n\
         \x20       aat_signature: [{aat_signature}],\n\
         \x20       session_id_r: {session_id_r},\n\
         \x20   }}\n\
         }}",
        user_pk = user_pk.join(", "),
        siblings = siblings.join(", "),
        claims = claims.join(", "),
        sub_blinding_factor = dec(fixture.sub_blinding_factor),
        credential_commitment = dec(fixture.credential_commitment),
        live_commitment = dec(fixture.live_commitment),
        sec_flags = fixture.sec_flags,
        assertion_x = byte_list(assertion_point.x().unwrap()),
        assertion_y = byte_list(assertion_point.y().unwrap()),
        aat_signature = byte_list(&fixture.aat_signature),
        session_id_r = dec(fixture.session_id_r),
    )
    .unwrap();

    out
}

fn noir_package_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("noir/embedding-similarity/{file}"))
}

#[test]
fn prover_toml_matches_the_fixture() {
    let fixture = fixture();
    let rendered = render_prover_toml(&fixture);
    let path = noir_package_path("Prover.toml");

    if env::var_os("UPDATE_PROVER_TOML").is_some() {
        fs::write(&path, &rendered)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
        let noir_path = noir_package_path("src/test_fixtures.nr");
        fs::write(&noir_path, render_noir_fixtures(&fixture))
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", noir_path.display()));
        return;
    }

    let committed = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    assert_eq!(
        committed,
        rendered,
        "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof \
         embedding_similarity` (and re-run `nargo fmt` for src/test_fixtures.nr)",
        path.display()
    );
}

/// Pins the WIP-111/WIP-110 domain separators to the integers hardcoded in the
/// Noir package so the two implementations cannot silently diverge.
#[test]
fn domain_separators_match_the_noir_constants() {
    let as_int = |tag: &[u8]| dec_fq(ark_babyjubjub::Fq::from_be_bytes_mod_order(tag));
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
