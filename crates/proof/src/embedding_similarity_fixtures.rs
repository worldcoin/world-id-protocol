//! Fixture generator for the WIP-202 Proof of Embedding Similarity circuit
//! (`noir/embedding-similarity`): one coherent witness spanning the WIP-201 Flamingo Token,
//! the account, the PCP `hashes.json` and the PoH Credential, plus the signed variants the
//! Noir tests need.
//!
//! The Flamingo Token reuses the WIP-201 test vectors, so its digests are pinned to the spec.
//! The Credential claim is computed by `Credential::claim` over the raw `hashes.json` bytes,
//! so the circuit's sponge is checked against the Issuer's implementation.
//! Regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity`.

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use ark_ff::PrimeField;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use sha2::{Digest, Sha256};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, DomainSeparator, FieldElement,
    poseidon::{self, ds},
};
use world_id_test_utils::merkle::first_leaf_merkle_path;

/// The WIP-201 digest runs at `t=16`, so the separator pins 15 inputs.
const DS_WIP_201: DomainSeparator<15> = DomainSeparator::new(b"WORLD-ID/WIP-201/SIGN");
const DS_WIP_202_AUTH: DomainSeparator<4> = DomainSeparator::new(b"WORLD-ID/WIP-202/AUTH");

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

// WIP-201 Appendix A1 values.
const NOW: u32 = 1_783_446_000;
const RP_ID: u64 = 1_928_118;
const NONCE: u64 = 42;
const PLATFORM: u8 = 2;
const SEC_LEVEL: u8 = 1;
const SEC_META: u8 = 3;
/// `user_presence` 2 with provider bits `0b01`.
const AUTHENTICATOR_META: u8 = 10;
const ENGINE_CONFIG_HASH: &str = "2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d";
const TRUST_ANCHOR_KEY_HASH: &str =
    "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
/// Compared entry 1 is pipeline input 0; the circuit hardcodes it (WIP-202 §4.3).
const COMPARE_SOURCES: u32 = 256;
const DIGEST_WITH_AAT: &str = "24a02c43c27878dc6623224138ec390efe9044be4271c8a2f82bb5a78910bc4f";
const DIGEST_WITHOUT_AAT: &str = "045442bd20ef9bbcf96e1d5534508467891d17532204659aa56e80c8a5ff0b06";
const CREDENTIAL_IMAGE: &[u8] = b"credential image";
const LIVE_IMAGE: &[u8] = b"live image";
const CHALLENGE_IMAGE: &[u8] = b"challenge image";
/// The RP's signal, hashed as for Uniqueness Proofs.
const SIGNAL: &[u8] = b"rp signal";

const LEAF_INDEX: u64 = 1;
const GENESIS_ISSUED_AT: u64 = 1_600_000_000;
const GENESIS_ISSUED_AT_MIN: u64 = 1_500_000_000;
/// The RP's minimum expiration; WIP-118 defaults it to the request's `created_at`.
const EXPIRES_AT_MIN: u32 = NOW;
const EXPIRES_AT: u32 = 1_900_000_000;
const ISSUER_SCHEMA_ID: u64 = 4_242;
const ISSUER_VERSION: u8 = 1;
const CRED_ID: u64 = 7;

fn dec(element: impl Into<ark_babyjubjub::Fq>) -> String {
    element.into().into_bigint().to_string()
}

fn from_hex(hex: &str) -> FieldElement {
    ark_babyjubjub::Fq::from_be_bytes_mod_order(&hex::decode(hex).unwrap()).into()
}

/// `R(SHA-256(bytes))`: the digest read as a big-endian integer modulo p (WIP-201).
fn sha256_field(bytes: &[u8]) -> FieldElement {
    ark_babyjubjub::Fq::from_be_bytes_mod_order(&Sha256::digest(bytes)).into()
}

fn sig(signature: &EdDSASignature) -> (String, String) {
    (
        signature.s.into_bigint().to_string(),
        format!("[{}, {}]", dec(signature.r.x), dec(signature.r.y)),
    )
}

fn noir_sig(signature: &EdDSASignature) -> String {
    let (s, r) = sig(signature);
    format!("Signature {{ s: {s}, r: {r} }}")
}

fn toml_sig(signature: &EdDSASignature) -> String {
    let (s, r) = sig(signature);
    format!("s = \"{s}\"\nr = {}", quoted(&r))
}

fn noir_point(pk: &EdDSAPublicKey) -> String {
    format!("PublicKey {{ x: {}, y: {} }}", dec(pk.pk.x), dec(pk.pk.y))
}

fn toml_point(pk: &EdDSAPublicKey) -> String {
    format!("x = \"{}\"\ny = \"{}\"", dec(pk.pk.x), dec(pk.pk.y))
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

/// `min_build_version` (bits 16-47) is 0, since WIP-202 fixes it to 0.
fn aat_flags() -> u64 {
    u64::from(PLATFORM)
        + (u64::from(SEC_LEVEL) << 8)
        + (u64::from(SEC_META) << 48)
        + (u64::from(AUTHENTICATOR_META) << 52)
}

/// The WIP-201 signed digest of a Flamingo Token over the fixture request, signed at `now`.
fn token_digest(has_aat: bool, now: u32, compared: [FieldElement; 4]) -> FieldElement {
    let aat = |value: FieldElement| if has_aat { value } else { FieldElement::ZERO };
    let mut claims = [FieldElement::ZERO; 15];
    claims[0] = FieldElement::from(u64::from(now));
    claims[1..5].copy_from_slice(&compared);
    claims[5] = FieldElement::from(RP_ID);
    claims[6] = FieldElement::from(NONCE);
    claims[7] = aat(from_hex(TRUST_ANCHOR_KEY_HASH));
    claims[8] = aat(FieldElement::from(aat_flags()));
    claims[9] = FieldElement::from(u64::from(has_aat));
    claims[10] = FieldElement::from(u64::from(COMPARE_SOURCES));
    claims[11] = from_hex(ENGINE_CONFIG_HASH);
    poseidon::hash(DS_WIP_201, claims)
}

/// The account's authorization message for a Flamingo Token digest and the RP's signal.
fn authorization_message(
    digest: FieldElement,
    verifier_key: &EdDSAPublicKey,
    signal_hash: FieldElement,
) -> FieldElement {
    poseidon::hash(
        DS_WIP_202_AUTH,
        [
            digest,
            verifier_key.pk.x.into(),
            verifier_key.pk.y.into(),
            signal_hash,
        ],
    )
}

fn compared() -> [FieldElement; 4] {
    [
        sha256_field(CREDENTIAL_IMAGE),
        sha256_field(LIVE_IMAGE),
        sha256_field(CHALLENGE_IMAGE),
        FieldElement::ZERO,
    ]
}

/// A compact, sorted v3 PCP `hashes.json` whose thumbnail is the compared Credential image.
fn hashes_json() -> (Vec<u8>, usize) {
    let mut entries: BTreeMap<&str, String> = PCP_V3_KEYS
        .iter()
        .map(|key| (*key, hex::encode(Sha256::digest(key.as_bytes()))))
        .collect();
    entries.insert(
        "thumbnail.png",
        hex::encode(Sha256::digest(CREDENTIAL_IMAGE)),
    );
    entries.insert("version", "3.0".into());
    let json = format!(
        "{{{}}}",
        entries
            .iter()
            .map(|(key, value)| format!("\"{key}\":\"{value}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    // The digest starts after the 17-byte key `"thumbnail.png":"`.
    let offset = json.find("\"thumbnail.png\":\"").unwrap() + 17;
    (json.into_bytes(), offset)
}

struct Rendered {
    toml: String,
    noir: String,
}

#[expect(clippy::too_many_lines)]
fn render() -> Rendered {
    // Deterministic test keys, not real key material. The Verifier key is WIP-201's.
    let authenticator_sk = EdDSAPrivateKey::from_bytes([42_u8; 32]);
    let issuer_sk = EdDSAPrivateKey::from_bytes([13_u8; 32]);
    let verifier_sk = EdDSAPrivateKey::from_bytes([0x15_u8; 32]);
    let verifier_key = verifier_sk.public();

    let key_set = AuthenticatorPublicKeySet::new(vec![authenticator_sk.public()]).unwrap();
    let (siblings, merkle_root) = first_leaf_merkle_path(key_set.leaf_hash());

    let compared = compared();
    let (hashes_json, digest_offset) = hashes_json();

    let digest = token_digest(true, NOW, compared);
    let digest_no_aat = token_digest(false, NOW, compared);
    // Signed when the Credential expires, so only the validity check rejects it.
    let digest_at_expiry = token_digest(true, EXPIRES_AT, compared);
    let token = verifier_sk.sign(*digest);
    let token_no_aat = verifier_sk.sign(*digest_no_aat);
    let token_at_expiry = verifier_sk.sign(*digest_at_expiry);
    let signal_hash = FieldElement::from_arbitrary_raw_bytes(SIGNAL);
    let auth = authenticator_sk.sign(*authorization_message(digest, &verifier_key, signal_hash));
    let auth_no_aat = authenticator_sk.sign(*authorization_message(
        digest_no_aat,
        &verifier_key,
        signal_hash,
    ));
    let auth_no_signal = authenticator_sk.sign(*authorization_message(
        digest,
        &verifier_key,
        FieldElement::ZERO,
    ));
    let auth_at_expiry = authenticator_sk.sign(*authorization_message(
        digest_at_expiry,
        &verifier_key,
        signal_hash,
    ));

    let sub_blinding_factor = FieldElement::from(777_u64);
    let credential = Credential::new()
        .id(CRED_ID)
        .issuer_version(ISSUER_VERSION)
        .issuer_schema_id(ISSUER_SCHEMA_ID)
        .subject(Credential::compute_sub(LEAF_INDEX, sub_blinding_factor))
        .genesis_issued_at(GENESIS_ISSUED_AT)
        .expires_at(u64::from(EXPIRES_AT))
        .claim(0, &hashes_json)
        .unwrap()
        .sign(&issuer_sk)
        .unwrap();
    let cred_sig = credential.signature.as_ref().unwrap();

    let session_id_r = FieldElement::from(555_u64);
    let session_id = poseidon::hash(
        ds::SESSION_COMMITMENT,
        [FieldElement::from(LEAF_INDEX), session_id_r],
    );

    let claim_0 = dec(*credential.claims[0]);
    let chunk_list = list(chunks(&hashes_json).iter().map(|c| dec(**c)));
    let siblings_list = list(siblings.iter().map(|s| dec(**s)));
    let takh = dec(*from_hex(TRUST_ANCHOR_KEY_HASH));
    let engine_config_hash = dec(*from_hex(ENGINE_CONFIG_HASH));

    #[rustfmt::skip]
    let globals: Vec<(&str, &str, String)> = vec![
        // Public inputs
        ("FLAMINGO_VERIFIER_KEY", "PublicKey", noir_point(&verifier_key)),
        ("NOW", "u32", NOW.to_string()),
        ("RP_ID", "Field", RP_ID.to_string()),
        ("NONCE", "Field", NONCE.to_string()),
        ("TRUST_ANCHOR_KEY_HASH", "Field", takh.clone()),
        ("PLATFORM", "u8", PLATFORM.to_string()),
        ("SEC_LEVEL", "u8", SEC_LEVEL.to_string()),
        ("SEC_META", "u8", SEC_META.to_string()),
        ("AUTHENTICATOR_META", "u8", AUTHENTICATOR_META.to_string()),
        ("ENGINE_CONFIG_HASH", "Field", engine_config_hash.clone()),
        ("CHALLENGE_HASH", "Field", dec(*compared[2])),
        ("SIGNAL_HASH", "Field", dec(*signal_hash)),
        ("MERKLE_ROOT", "Field", dec(*merkle_root)),
        ("ISSUER_SCHEMA_ID", "Field", ISSUER_SCHEMA_ID.to_string()),
        ("ISSUER_VERSION", "Field", ISSUER_VERSION.to_string()),
        ("CRED_PK", "PublicKey", noir_point(&credential.issuer)),
        ("GENESIS_ISSUED_AT_MIN", "Field", GENESIS_ISSUED_AT_MIN.to_string()),
        ("EXPIRES_AT_MIN", "Field", EXPIRES_AT_MIN.to_string()),
        ("SESSION_ID", "Field", dec(*session_id)),
        // Flamingo Token witness
        ("LIVE_CAPTURE_HASH", "Field", dec(*compared[1])),
        ("TOKEN_SIG", "Signature", noir_sig(&token)),
        // Account witness
        ("USER_PK", "PublicKey", noir_point(&authenticator_sk.public())),
        ("AUTH_SIG", "Signature", noir_sig(&auth)),
        ("LEAF_INDEX", "Field", LEAF_INDEX.to_string()),
        ("SIBLINGS", "[Field; 30]", siblings_list.clone()),
        // Credential witness (claims are zero except `claims[0]`)
        ("CLAIM_0", "Field", claim_0.clone()),
        ("GENESIS_ISSUED_AT", "Field", GENESIS_ISSUED_AT.to_string()),
        ("EXPIRES_AT", "Field", EXPIRES_AT.to_string()),
        ("SUB_BLINDING_FACTOR", "Field", dec(*sub_blinding_factor)),
        ("CRED_ID", "Field", CRED_ID.to_string()),
        ("CRED_SIG", "Signature", noir_sig(cred_sig)),
        // hashes.json witness
        ("HASHES_JSON_CHUNKS", "[Field; 169]", chunk_list.clone()),
        ("HASHES_JSON_LEN", "u32", hashes_json.len().to_string()),
        ("DIGEST_OFFSET", "u32", digest_offset.to_string()),
        ("SESSION_ID_R", "Field", dec(*session_id_r)),
        // Signed variants for the tests
        ("TOKEN_SIG_NO_AAT", "Signature", noir_sig(&token_no_aat)),
        ("AUTH_SIG_NO_AAT", "Signature", noir_sig(&auth_no_aat)),
        ("AUTH_SIG_NO_SIGNAL", "Signature", noir_sig(&auth_no_signal)),
        ("TOKEN_SIG_AT_EXPIRY", "Signature", noir_sig(&token_at_expiry)),
        ("AUTH_SIG_AT_EXPIRY", "Signature", noir_sig(&auth_at_expiry)),
    ];

    let noir = format!(
        "// GENERATED FILE: one coherent WIP-202 witness plus the signed variants the tests\n\
         // need. Regenerate with:\n\
         //   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity\n\
         // Keys derive from constant test seeds (not real key material).\n\
         use world_id_components::types::{{PublicKey, Signature}};\n\n{}",
        globals
            .iter()
            .map(|(name, ty, value)| format!("pub global {name}: {ty} = {value};\n"))
            .collect::<String>()
    );

    let user_pk = std::iter::once(toml_point(&authenticator_sk.public()))
        .chain(std::iter::repeat_n("x = \"0\"\ny = \"1\"".to_string(), 6))
        .map(|point| format!("\n[[inputs.account.user_pk]]\n{point}\n"))
        .collect::<String>();
    let mut claims = vec!["\"0\"".to_string(); Credential::MAX_CLAIMS];
    claims[0] = format!("\"{claim_0}\"");

    let toml = format!(
        "# Prover.toml for the WIP-202 Proof of Embedding Similarity circuit.\n\
         #\n\
         # GENERATED FILE. Do not edit by hand; regenerate with:\n\
         #   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity\n\
         \n\
         # Public inputs\n\
         now = \"{NOW}\"\n\
         rp_id = \"{RP_ID}\"\n\
         nonce = \"{NONCE}\"\n\
         has_aat = true\n\
         trust_anchor_key_hash = \"{takh}\"\n\
         platform = \"{PLATFORM}\"\n\
         sec_level = \"{SEC_LEVEL}\"\n\
         sec_meta = \"{SEC_META}\"\n\
         authenticator_meta = \"{AUTHENTICATOR_META}\"\n\
         engine_config_hash = \"{engine_config_hash}\"\n\
         challenge_hash = \"{challenge_hash}\"\n\
         signal_hash = \"{signal_hash}\"\n\
         merkle_root = \"{merkle_root}\"\n\
         issuer_schema_id = \"{ISSUER_SCHEMA_ID}\"\n\
         issuer_version = \"{ISSUER_VERSION}\"\n\
         genesis_issued_at_min = \"{GENESIS_ISSUED_AT_MIN}\"\n\
         expires_at_min = \"{EXPIRES_AT_MIN}\"\n\
         session_id = \"{session_id}\"\n\
         \n\
         [flamingo_verifier_key]\n{verifier_key}\n\
         \n\
         [cred_pk]\n{cred_pk}\n\
         \n\
         # Private inputs\n\
         [inputs]\n\
         session_id_r = \"{session_id_r}\"\n\
         \n\
         [inputs.token]\n\
         live_capture_hash = \"{live_capture_hash}\"\n\
         \n\
         [inputs.token.sig]\n{token_sig}\n\
         \n\
         [inputs.account]\n\
         pk_index = \"0\"\n\
         leaf_index = \"{LEAF_INDEX}\"\n\
         siblings = {siblings}\n\
         \n\
         [inputs.account.auth]\n{auth_sig}\n\
         {user_pk}\
         \n\
         [inputs.credential]\n\
         claims = [{claims}]\n\
         associated_data_hash = \"0\"\n\
         genesis_issued_at = \"{GENESIS_ISSUED_AT}\"\n\
         expires_at = \"{EXPIRES_AT}\"\n\
         sub_blinding_factor = \"{sub_blinding_factor}\"\n\
         id = \"{CRED_ID}\"\n\
         \n\
         [inputs.credential.sig]\n{cred_sig}\n\
         \n\
         [inputs.hashes_json]\n\
         chunks = {chunks}\n\
         len = \"{len}\"\n\
         digest_offset = \"{digest_offset}\"\n",
        challenge_hash = dec(*compared[2]),
        signal_hash = dec(*signal_hash),
        merkle_root = dec(*merkle_root),
        session_id = dec(*session_id),
        verifier_key = toml_point(&verifier_key),
        cred_pk = toml_point(&credential.issuer),
        session_id_r = dec(*session_id_r),
        live_capture_hash = dec(*compared[1]),
        token_sig = toml_sig(&token),
        siblings = quoted(&siblings_list),
        auth_sig = toml_sig(&auth),
        claims = claims.join(", "),
        sub_blinding_factor = dec(*sub_blinding_factor),
        cred_sig = toml_sig(cred_sig),
        chunks = quoted(&chunk_list),
        len = hashes_json.len(),
    );

    Rendered { toml, noir }
}

#[test]
fn prover_toml_matches_the_fixture() {
    let rendered = render();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("noir/embedding-similarity");
    let artifacts = [
        ("Prover.toml", &rendered.toml, true),
        ("src/test_fixtures.nr", &rendered.noir, false),
    ];
    for (file, content, check) in artifacts {
        let path = dir.join(file);
        if env::var_os("UPDATE_PROVER_TOML").is_some() {
            fs::write(&path, content)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            continue;
        }
        // `nargo fmt` reformats the generated Noir file, so only the TOML is compared.
        if check {
            let committed = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            assert_eq!(
                &committed,
                content,
                "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p \
                 world-id-proof embedding_similarity` (and re-run `nargo fmt`)",
                path.display()
            );
        }
    }
}

/// The fixture's Flamingo Tokens are the WIP-201 Appendix A1 test vectors.
#[test]
fn token_digests_match_the_wip_201_vectors() {
    assert_eq!(
        token_digest(true, NOW, compared()),
        from_hex(DIGEST_WITH_AAT)
    );
    assert_eq!(
        token_digest(false, NOW, compared()),
        from_hex(DIGEST_WITHOUT_AAT)
    );
    assert_eq!(aat_flags(), 0x00a3_0000_0000_0102);
}

/// Pins the domain separators to the integers hardcoded in the Noir package.
#[test]
fn domain_separators_match_the_noir_constants() {
    let as_int = |tag: &[u8]| dec(ark_babyjubjub::Fq::from_be_bytes_mod_order(tag));
    assert_eq!(
        as_int(b"WORLD-ID/WIP-201/SIGN"),
        "127603488023523044162070750169730750022280897185614"
    );
    assert_eq!(
        as_int(b"WORLD-ID/WIP-202/AUTH"),
        "127603488023523044162070750169730750023380107613256"
    );
}
