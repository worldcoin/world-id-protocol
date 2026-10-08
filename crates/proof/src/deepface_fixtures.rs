//! Fixture generator for the WIP-111 DeepFace circuit (`noir/deepface`): one coherent
//! witness spanning the WIP-110 Verifier token, the WIP-106 AAT, the PCP `hashes.json`,
//! the Credential and the registry, plus the signed variants the Noir negative tests need.
//!
//! The Credential claim is computed by `Credential::claim` over the raw `hashes.json`
//! bytes, so the circuit's sponge is checked against the Issuer's implementation.
//! Regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof deepface`.

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use ark_ff::PrimeField;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use sha2::{Digest, Sha256};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, DomainSeparator, FieldElement,
    poseidon::{self, ds},
};
use world_id_test_utils::merkle::first_leaf_merkle_path;

use crate::authenticator_assertion::{
    AuthenticatorAssertionPrivateInputs, AuthenticatorAssertionPublicInputs,
    AuthenticatorAssertionToken, Platform, SecFlags, SecLevel, UserPresence,
    authenticator_provider_key_hash, request_commitment, verify_aat,
};

const DS_WIP_111: DomainSeparator<3> = DomainSeparator::new(b"WORLD-ID/WIP-111/SIGN");
/// The WIP-110 token digest runs at `t=16`, so the separator pins 15 inputs.
const DS_EVT_V1: DomainSeparator<15> = DomainSeparator::new(b"WORLD_ID_EVT_V1");

/// Chunk slots of the Noir `HashesJsonInputs` (`CHUNK_SLOTS`).
const CHUNK_SLOTS: usize = 169;
const CHUNK_BYTES: usize = 31;

/// The `hashes.json` keys of a v3 PCP as written by orb-core, besides `version`.
const PCP_V3_KEYS: [&str; 44] = [
    "backend_keys.json",
    "face_embeddings.json",
    "iris_code_shares_0.json",
    "iris_code_shares_1.json",
    "iris_code_shares_2.json",
    "iris_codes.json",
    "left_ir.png",
    "left_normalized_image.bin",
    "left_normalized_image_blinding_factors.bin",
    "left_normalized_image_blinding_factors_resized.bin",
    "left_normalized_image_commitment.bin",
    "left_normalized_image_commitment_resized.bin",
    "left_normalized_image_resized.bin",
    "left_normalized_mask.bin",
    "left_normalized_mask_blinding_factors.bin",
    "left_normalized_mask_blinding_factors_resized.bin",
    "left_normalized_mask_commitment.bin",
    "left_normalized_mask_commitment_resized.bin",
    "left_normalized_mask_resized.bin",
    "orb_country",
    "orb_id",
    "qr_code",
    "right_ir.png",
    "right_normalized_image.bin",
    "right_normalized_image_blinding_factors.bin",
    "right_normalized_image_blinding_factors_resized.bin",
    "right_normalized_image_commitment.bin",
    "right_normalized_image_commitment_resized.bin",
    "right_normalized_image_resized.bin",
    "right_normalized_mask.bin",
    "right_normalized_mask_blinding_factors.bin",
    "right_normalized_mask_blinding_factors_resized.bin",
    "right_normalized_mask_commitment.bin",
    "right_normalized_mask_commitment_resized.bin",
    "right_normalized_mask_resized.bin",
    "signup_id",
    "software_version",
    "thumbnail.png",
    "tier_1",
    "tier_2",
    "tier_3",
    "tier_4",
    "tier_5",
    "timestamp",
];

const LEAF_INDEX: u64 = 1;
const AUD: u64 = 1_928_118;
const NOW: u64 = 1_700_000_000;
const IAT: u64 = NOW - 60;
const AAT_EXP: u32 = 1_700_000_900;
/// The AAT's `build_version`, also the fixture's `min_build_version`.
const BUILD_VERSION: u32 = 2006;
const SEC_META: u8 = 3;
const METHOD: u64 = 1;
const ASSURANCE_LEVEL: u64 = 2;
const ASSURANCE_LEVEL_MIN: u64 = 2;
const GENESIS_ISSUED_AT: u64 = 1_600_000_000;
const EXPIRES_AT: u64 = 1_800_000_000;
const ISSUER_SCHEMA_ID: u64 = 4_242;
const ISSUER_VERSION: u8 = 1;
const CRED_ID: u64 = 7;

fn dec(element: impl Into<ark_babyjubjub::Fq>) -> String {
    element.into().into_bigint().to_string()
}

/// `R(SHA-256(bytes))`: the digest read as a big-endian integer modulo p (WIP-110).
fn sha256_field(bytes: &[u8]) -> FieldElement {
    ark_babyjubjub::Fq::from_be_bytes_mod_order(&Sha256::digest(bytes)).into()
}

fn sig(signature: &EdDSASignature) -> (String, String) {
    (
        signature.s.into_bigint().to_string(),
        format!("[{}, {}]", dec(signature.r.x), dec(signature.r.y)),
    )
}

fn noir_point(pk: &EdDSAPublicKey) -> String {
    format!("PublicKey {{ x: {}, y: {} }}", dec(pk.pk.x), dec(pk.pk.y))
}

fn toml_point(pk: &EdDSAPublicKey) -> String {
    format!("x = \"{}\"\ny = \"{}\"", dec(pk.pk.x), dec(pk.pk.y))
}

/// A Noir `pub global` laid out as `nargo fmt` does at its 100-column width.
fn noir_global(name: &str, ty: &str, value: &str) -> String {
    let line = format!("pub global {name}: {ty} = {value};\n");
    if line.len() <= 101 {
        return line;
    }
    let head = format!("pub global {name}: {ty} =");
    let lines =
        |items: &str| -> String { items.split(", ").map(|i| format!("    {i},\n")).collect() };
    if let Some(fields) = value
        .strip_prefix("PublicKey { ")
        .and_then(|v| v.strip_suffix(" }"))
    {
        format!("{head} PublicKey {{\n{}}};\n", lines(fields))
    } else if let Some(items) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        format!("{head} [\n{}];\n", lines(items))
    } else {
        format!("{head}\n    {value};\n")
    }
}

fn list(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(", "))
}

fn quoted(values: &str) -> String {
    list(
        values
            .trim_matches(['[', ']'])
            .split(", ")
            .map(|v| format!("\"{v}\"")),
    )
}

/// The sponge chunks of `bytes`: 31-byte big-endian integers, zero-padded to the slots.
fn chunks(bytes: &[u8]) -> Vec<FieldElement> {
    let mut chunks: Vec<FieldElement> = bytes
        .chunks(CHUNK_BYTES)
        .map(|chunk| ark_babyjubjub::Fq::from_be_bytes_mod_order(chunk).into())
        .collect();
    chunks.resize(CHUNK_SLOTS, FieldElement::ZERO);
    chunks
}

fn token_signature(
    verifier_sk: &EdDSAPrivateKey,
    iat: u64,
    assurance_level: u64,
    request_hash: FieldElement,
    compared: [FieldElement; 4],
) -> EdDSASignature {
    let mut claims = [FieldElement::ZERO; 15];
    claims[0] = FieldElement::from(iat);
    claims[1] = FieldElement::from(METHOD);
    claims[2] = FieldElement::from(assurance_level);
    claims[3] = request_hash;
    claims[4..8].copy_from_slice(&compared);
    verifier_sk.sign(*poseidon::hash(DS_EVT_V1, claims))
}

struct Rendered {
    toml: String,
    noir: String,
}

#[expect(clippy::too_many_lines)]
fn render() -> Rendered {
    // Deterministic test keys, not real key material.
    let authenticator_sk = EdDSAPrivateKey::from_bytes([42_u8; 32]);
    let issuer_sk = EdDSAPrivateKey::from_bytes([13_u8; 32]);
    let verifier_sk = EdDSAPrivateKey::from_bytes([21_u8; 32]);
    let authenticator_provider_sk = EdDSAPrivateKey::from_bytes([7_u8; 32]);
    let authenticator_provider_pk = authenticator_provider_sk.public();

    let key_set = AuthenticatorPublicKeySet::new(vec![authenticator_sk.public()]).unwrap();
    let (siblings, merkle_root) = first_leaf_merkle_path(key_set.leaf_hash());

    // The compared entries and a v3 PCP `hashes.json`: compact, sorted, lowercase hex.
    let thumbnail = b"orb thumbnail png";
    let live = b"live capture";
    let challenge = b"rp challenge frame";
    let mut entries: BTreeMap<&str, String> = PCP_V3_KEYS
        .iter()
        .map(|key| (*key, hex::encode(Sha256::digest(key.as_bytes()))))
        .collect();
    entries.insert("thumbnail.png", hex::encode(Sha256::digest(thumbnail)));
    entries.insert("version", "3.0".into());
    let hashes_json = format!(
        "{{{}}}",
        entries
            .iter()
            .map(|(key, value)| format!("\"{key}\":\"{value}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let thumbnail_offset = hashes_json.find("\"thumbnail.png\"").unwrap();
    let hashes_json = hashes_json.into_bytes();

    let request_hash = sha256_field(b"sealed request plaintext");
    let compared = [
        sha256_field(thumbnail),
        sha256_field(live),
        sha256_field(challenge),
        FieldElement::ZERO,
    ];
    let mut compared_two_way = compared;
    compared_two_way[2] = FieldElement::ZERO;

    let nonce = FieldElement::from(0x11d2_23ce_7b91_ac21_u64);
    let aud = FieldElement::from(AUD);
    let authorization =
        authenticator_sk.sign(*poseidon::hash(DS_WIP_111, [request_hash, nonce, aud]));

    let sec_flags = SecFlags::new(
        Platform::Ios.into(),
        SecLevel::HardwareKey.into(),
        BUILD_VERSION,
        SEC_META,
        UserPresence::PresentVerified,
    )
    .unwrap();
    let aat_blind = FieldElement::from(999_u64);
    let aat = AuthenticatorAssertionToken::new(
        AAT_EXP,
        request_commitment(aud, nonce, request_hash, aat_blind),
        sec_flags,
    )
    .unwrap();
    let aat_sig = authenticator_provider_sk.sign(*aat.message_hash());
    let key_hash = authenticator_provider_key_hash(&authenticator_provider_pk);
    // The Rust reference verifier must accept the AAT witness the circuit gets.
    verify_aat(
        &AuthenticatorAssertionPublicInputs {
            authenticator_provider_key_hash: key_hash,
            now: u32::try_from(NOW).unwrap(),
            aud,
            nonce,
            platform: sec_flags.platform(),
            sec_level: sec_flags.sec_level(),
            sec_meta: SEC_META,
            user_presence: sec_flags.user_presence(),
            min_build_version: BUILD_VERSION,
        },
        &AuthenticatorAssertionPrivateInputs {
            authenticator_provider_key: authenticator_provider_pk.clone(),
            exp: AAT_EXP,
            sec_flags: sec_flags.pack(),
            sig: aat_sig.clone(),
            cdh: request_hash,
            blind: aat_blind,
        },
    )
    .unwrap();
    let provider_key = format!(
        "[{}, {}]",
        dec(authenticator_provider_pk.pk.x),
        dec(authenticator_provider_pk.pk.y)
    );

    let sub_blinding_factor = FieldElement::from(777_u64);
    let credential = Credential::new()
        .id(CRED_ID)
        .issuer_version(ISSUER_VERSION)
        .issuer_schema_id(ISSUER_SCHEMA_ID)
        .subject(Credential::compute_sub(LEAF_INDEX, sub_blinding_factor))
        .genesis_issued_at(GENESIS_ISSUED_AT)
        .expires_at(EXPIRES_AT)
        .claim(0, &hashes_json)
        .unwrap()
        .sign(&issuer_sk)
        .unwrap();

    let session_id_r = FieldElement::from(555_u64);
    let session_id = poseidon::hash(
        ds::SESSION_COMMITMENT,
        [FieldElement::from(LEAF_INDEX), session_id_r],
    );

    let token = token_signature(&verifier_sk, IAT, ASSURANCE_LEVEL, request_hash, compared);
    let token_two_way = token_signature(
        &verifier_sk,
        IAT,
        ASSURANCE_LEVEL,
        request_hash,
        compared_two_way,
    );
    let token_low_level = token_signature(&verifier_sk, IAT, 1, request_hash, compared);
    let token_future_iat = token_signature(
        &verifier_sk,
        NOW + 10,
        ASSURANCE_LEVEL,
        request_hash,
        compared,
    );

    let (auth_s, auth_r) = sig(&authorization);
    let (cred_s, cred_r) = sig(credential.signature.as_ref().unwrap());
    let (token_s, token_r) = sig(&token);
    let (token2_s, token2_r) = sig(&token_two_way);
    let (tokenl_s, tokenl_r) = sig(&token_low_level);
    let (tokenf_s, tokenf_r) = sig(&token_future_iat);
    let (aat_s, aat_r) = sig(&aat_sig);

    let claim_0 = dec(*credential.claims[0]);
    let chunk_list = list(chunks(&hashes_json).iter().map(|c| dec(**c)));
    let compared_list = list(compared.iter().map(|c| dec(**c)));
    let siblings_list = list(siblings.iter().map(|s| dec(**s)));

    #[rustfmt::skip]
    let globals: Vec<(&str, &str, String)> = vec![
        // Public inputs
        ("VERIFIER_KEY", "PublicKey", noir_point(&verifier_sk.public())),
        ("METHOD", "Field", METHOD.to_string()),
        ("ASSURANCE_LEVEL_MIN", "Field", ASSURANCE_LEVEL_MIN.to_string()),
        ("COMPARISON_AGE_MAX", "Field", "300".into()),
        ("CHALLENGE_HASH", "Field", dec(*compared[2])),
        ("NOW", "Field", NOW.to_string()),
        ("AUTHENTICATOR_PROVIDER_KEY_HASH", "Field", dec(*key_hash)),
        ("AUD", "Field", AUD.to_string()),
        ("NONCE", "Field", dec(*nonce)),
        ("PLATFORM", "u8", sec_flags.platform().to_string()),
        ("SEC_LEVEL", "u8", sec_flags.sec_level().to_string()),
        ("SEC_META", "u8", SEC_META.to_string()),
        ("USER_PRESENCE", "u8", u8::from(sec_flags.user_presence()).to_string()),
        ("MIN_BUILD_VERSION", "u32", BUILD_VERSION.to_string()),
        ("MERKLE_ROOT", "Field", dec(*merkle_root)),
        ("ISSUER_SCHEMA_ID", "Field", ISSUER_SCHEMA_ID.to_string()),
        ("ISSUER_VERSION", "Field", ISSUER_VERSION.to_string()),
        ("CRED_PK", "PublicKey", noir_point(&credential.issuer)),
        ("GENESIS_ISSUED_AT_MIN", "Field", "1500000000".into()),
        ("SESSION_ID", "Field", dec(*session_id)),
        // Registry witness
        ("USER_PK", "PublicKey", noir_point(&authenticator_sk.public())),
        ("AUTH_SIG_S", "Field", auth_s.clone()),
        ("AUTH_SIG_R", "[Field; 2]", auth_r.clone()),
        ("LEAF_INDEX", "Field", LEAF_INDEX.to_string()),
        ("SIBLINGS", "[Field; 30]", siblings_list.clone()),
        // Credential witness (claims are zero except `claims[0]`)
        ("CLAIM_0", "Field", claim_0.clone()),
        ("GENESIS_ISSUED_AT", "Field", GENESIS_ISSUED_AT.to_string()),
        ("EXPIRES_AT", "Field", EXPIRES_AT.to_string()),
        ("SUB_BLINDING_FACTOR", "Field", dec(*sub_blinding_factor)),
        ("CRED_ID", "Field", CRED_ID.to_string()),
        ("CRED_SIG_S", "Field", cred_s.clone()),
        ("CRED_SIG_R", "[Field; 2]", cred_r.clone()),
        // Verifier token witness
        ("IAT", "Field", IAT.to_string()),
        ("ASSURANCE_LEVEL", "Field", ASSURANCE_LEVEL.to_string()),
        ("REQUEST_HASH", "Field", dec(*request_hash)),
        ("COMPARED_ENTRY_HASH", "[Field; 4]", compared_list.clone()),
        ("TOKEN_SIG_S", "Field", token_s.clone()),
        ("TOKEN_SIG_R", "[Field; 2]", token_r.clone()),
        // AAT witness (`cdh` is `REQUEST_HASH`)
        ("AUTHENTICATOR_PROVIDER_KEY", "[Field; 2]", provider_key.clone()),
        ("AAT_EXP", "Field", AAT_EXP.to_string()),
        ("SEC_FLAGS", "Field", sec_flags.pack().to_string()),
        ("AAT_SIG_S", "Field", aat_s.clone()),
        ("AAT_SIG_R", "[Field; 2]", aat_r.clone()),
        ("AAT_BLIND", "Field", dec(*aat_blind)),
        // hashes.json witness
        ("HASHES_JSON_CHUNKS", "[Field; 169]", chunk_list.clone()),
        ("HASHES_JSON_LEN", "u32", hashes_json.len().to_string()),
        ("THUMBNAIL_OFFSET", "u32", thumbnail_offset.to_string()),
        ("SESSION_ID_R", "Field", dec(*session_id_r)),
        // Signed variants for the negative tests
        ("TOKEN_SIG_S_TWO_WAY", "Field", token2_s),
        ("TOKEN_SIG_R_TWO_WAY", "[Field; 2]", token2_r),
        ("TOKEN_SIG_S_LOW_LEVEL", "Field", tokenl_s),
        ("TOKEN_SIG_R_LOW_LEVEL", "[Field; 2]", tokenl_r),
        ("FUTURE_IAT", "Field", (NOW + 10).to_string()),
        ("TOKEN_SIG_S_FUTURE_IAT", "Field", tokenf_s),
        ("TOKEN_SIG_R_FUTURE_IAT", "[Field; 2]", tokenf_r),
    ];

    let noir = format!(
        "// GENERATED FILE: one coherent WIP-111 DeepFace witness plus the signed variants\n\
         // the negative tests need. Regenerate with:\n\
         //   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof deepface\n\
         // Keys derive from constant test seeds (not real key material).\n\
         use super::types::PublicKey;\n\n{}",
        globals
            .iter()
            .map(|(name, ty, value)| noir_global(name, ty, value))
            .collect::<String>()
    );

    let user_pk = std::iter::once(toml_point(&authenticator_sk.public()))
        .chain(std::iter::repeat_n("x = \"0\"\ny = \"1\"".to_string(), 6))
        .map(|point| format!("\n[[inputs.registry.user_pk]]\n{point}\n"))
        .collect::<String>();
    let mut claims = vec!["\"0\"".to_string(); Credential::MAX_CLAIMS];
    claims[0] = format!("\"{claim_0}\"");

    let toml = format!(
        "# Prover.toml for the DeepFace circuit (WIP-111).\n\
         #\n\
         # GENERATED FILE. Do not edit by hand; regenerate with:\n\
         #   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof deepface\n\
         \n\
         # Public inputs\n\
         method = \"{METHOD}\"\n\
         assurance_level_min = \"{ASSURANCE_LEVEL_MIN}\"\n\
         comparison_age_max = \"300\"\n\
         challenge_hash = \"{challenge_hash}\"\n\
         now = \"{NOW}\"\n\
         aud = \"{AUD}\"\n\
         nonce = \"{nonce}\"\n\
         authenticator_provider_key_hash = \"{key_hash}\"\n\
         platform = \"{platform}\"\n\
         sec_level = \"{sec_level}\"\n\
         sec_meta = \"{SEC_META}\"\n\
         user_presence = \"{user_presence}\"\n\
         min_build_version = \"{BUILD_VERSION}\"\n\
         merkle_root = \"{merkle_root}\"\n\
         issuer_schema_id = \"{ISSUER_SCHEMA_ID}\"\n\
         issuer_version = \"{ISSUER_VERSION}\"\n\
         genesis_issued_at_min = \"1500000000\"\n\
         session_id = \"{session_id}\"\n\
         \n\
         [verifier_key]\n{verifier_key}\n\
         \n\
         [cred_pk]\n{cred_pk}\n\
         \n\
         # Private inputs\n\
         [inputs]\n\
         session_id_r = \"{session_id_r}\"\n\
         \n\
         [inputs.registry]\n\
         pk_index = \"0\"\n\
         sig_s = \"{auth_s}\"\n\
         sig_r = {auth_r}\n\
         leaf_index = \"{LEAF_INDEX}\"\n\
         siblings = {siblings}\n\
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
         sig_r = {cred_r}\n\
         \n\
         [inputs.token]\n\
         iat = \"{IAT}\"\n\
         method = \"{METHOD}\"\n\
         assurance_level = \"{ASSURANCE_LEVEL}\"\n\
         request_hash = \"{request_hash}\"\n\
         compared_entry_hash = {compared}\n\
         sig_s = \"{token_s}\"\n\
         sig_r = {token_r}\n\
         \n\
         [inputs.aat]\n\
         authenticator_provider_key = {provider_key}\n\
         exp = \"{AAT_EXP}\"\n\
         sec_flags = \"{sec_flags}\"\n\
         sig_s = \"{aat_s}\"\n\
         sig_r = {aat_r}\n\
         cdh = \"{request_hash}\"\n\
         blind = \"{aat_blind}\"\n\
         \n\
         [inputs.hashes_json]\n\
         chunks = {chunks}\n\
         len = \"{len}\"\n\
         thumbnail_offset = \"{thumbnail_offset}\"\n",
        challenge_hash = dec(*compared[2]),
        nonce = dec(*nonce),
        key_hash = dec(*key_hash),
        platform = sec_flags.platform(),
        sec_level = sec_flags.sec_level(),
        user_presence = u8::from(sec_flags.user_presence()),
        merkle_root = dec(*merkle_root),
        session_id = dec(*session_id),
        verifier_key = toml_point(&verifier_sk.public()),
        cred_pk = toml_point(&credential.issuer),
        aat_blind = dec(*aat_blind),
        session_id_r = dec(*session_id_r),
        auth_r = quoted(&auth_r),
        siblings = quoted(&siblings_list),
        claims = claims.join(", "),
        sub_blinding_factor = dec(*sub_blinding_factor),
        cred_r = quoted(&cred_r),
        request_hash = dec(*request_hash),
        compared = quoted(&compared_list),
        token_r = quoted(&token_r),
        provider_key = quoted(&provider_key),
        sec_flags = sec_flags.pack(),
        aat_r = quoted(&aat_r),
        chunks = quoted(&chunk_list),
        len = hashes_json.len(),
    );

    Rendered { toml, noir }
}

#[test]
fn prover_toml_matches_the_fixture() {
    let rendered = render();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("noir/deepface");
    let artifacts = [
        ("Prover.toml", &rendered.toml),
        ("src/test_fixtures.nr", &rendered.noir),
    ];
    for (file, content) in artifacts {
        let path = dir.join(file);
        if env::var_os("UPDATE_PROVER_TOML").is_some() {
            fs::write(&path, content)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            continue;
        }
        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert_eq!(
            &committed,
            content,
            "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p \
             world-id-proof deepface`",
            path.display()
        );
    }
}

/// Pins the domain separators to the integers hardcoded in the Noir package.
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
}
