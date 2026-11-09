//! Fixture generator for the WIP-202 Proof of Embedding Similarity circuit
//! (`noir/embedding-similarity`): one coherent witness spanning the WIP-201 Flamingo Token,
//! the account, the PCP `hashes.json` and the PoH Credential, plus the signed variants the
//! Noir tests need.
//!
//! The Flamingo Token digest comes from `world-id-flamingo` over the WIP-201 test vectors, and the
//! billing nullifier from a real OPRF evaluation with `taceo-oprf`, so neither is re-implemented here.
//! The Credential claim is computed by `Credential::claim` over the raw `hashes.json` bytes,
//! so the circuit's sponge is checked against the Issuer's implementation.
//! Regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity`.
//!
//! [`embedding_similarity_fixture`] builds the same witness as a typed circuit input, which
//! `witness_matches_the_prover_toml` checks against the committed `Prover.toml`.

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use ark_ec::CurveGroup as _;
use ark_ff::PrimeField;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use provekit_common::{InputMap, InputValue};
use ruint::aliases::{U160, U256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use taceo_oprf::{
    core::oprf::{BlindedOprfResponse, BlindingFactor, client},
    types::OprfKeyId,
};
use world_id_flamingo::{DS_SIGN, FlamingoAatClaims, FlamingoClaims};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, EmbeddingSimilarityParams, FieldElement, OprfPrefix,
    POH_ISSUER_SCHEMA_ID, ProofRequest, ProofType, RequestItem, RequestVersion, SessionId,
    SessionRef, TREE_DEPTH,
    authenticator::oprf_query_digest,
    authenticator_assertion::AatPublicValues,
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
    rp::RpId,
};
use world_id_test_utils::merkle::first_leaf_merkle_path;

use crate::{
    NoirCircuitInput as _,
    circuit_inputs::{EmbeddingSimilarityCircuitInput, EmbeddingSimilarityRequestInputs},
    embedding_similarity_proof::{
        CHUNK_BYTES, CHUNK_SLOTS, CLAIM_INDEX, COMPARE_SOURCES, DIGEST_HEX_LEN,
        MAX_HASHES_JSON_BYTES, MIN_HASHES_JSON_BYTES, THUMBNAIL_KEY,
    },
    fixtures::toml_types::{PublicKey, Signature},
};

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
const DIGEST_WITH_AAT: &str = "24a02c43c27878dc6623224138ec390efe9044be4271c8a2f82bb5a78910bc4f";
const DIGEST_WITHOUT_AAT: &str = "045442bd20ef9bbcf96e1d5534508467891d17532204659aa56e80c8a5ff0b06";
/// WIP-201 Appendix A1 "Billed RP": the AAT vector with `billing_nullifier = 7`.
const DIGEST_BILLED_7: &str = "247f7f653466f20e24fbac90c9c36055c7036d2c8d26c100907164723c7bb118";
const CREDENTIAL_IMAGE: &[u8] = b"credential image";
const LIVE_IMAGE: &[u8] = b"live image";
const CHALLENGE_IMAGE: &[u8] = b"challenge image";
/// The RP's signal, hashed as for Uniqueness Proofs.
const SIGNAL: &[u8] = b"rp signal";

const LEAF_INDEX: u64 = 1;
const GENESIS_ISSUED_AT: u64 = 1_600_000_000;
const GENESIS_ISSUED_AT_MIN: u64 = 1_500_000_000;
/// The RP's minimum expiration; WIP-114 defaults it to the request's `created_at`.
const EXPIRES_AT_MIN: u32 = NOW;
const EXPIRES_AT: u32 = 1_900_000_000;
/// The PoH Credential, the one a WIP-202 request can name.
const ISSUER_SCHEMA_ID: u64 = POH_ISSUER_SCHEMA_ID;
const ISSUER_VERSION: u8 = 1;
const CRED_ID: u64 = 7;
/// A WIP-107 `billingAction`, and the test OPRF key and blinding factor of the billing query.
const BILLING_ACTION: u64 = 0x0b11;
const OPRF_KEY: u64 = 0x0b11_1ab5;
const BLINDING_FACTOR: u64 = 7;

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

fn noir_point(pk: &EdDSAPublicKey) -> String {
    format!("PublicKey {{ x: {}, y: {} }}", dec(pk.pk.x), dec(pk.pk.y))
}

fn list(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(", "))
}

/// The sponge chunks of `bytes`: 31-byte big-endian integers, zero-padded to the slots.
fn chunks(bytes: &[u8]) -> Vec<FieldElement> {
    assert!(
        bytes.len() <= MAX_HASHES_JSON_BYTES,
        "hashes.json has {} bytes, more than the {MAX_HASHES_JSON_BYTES} the circuit accepts",
        bytes.len()
    );
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
fn token_digest(
    has_aat: bool,
    now: u32,
    compared: [FieldElement; 4],
    billing_nullifier: FieldElement,
) -> FieldElement {
    FlamingoClaims {
        now,
        compared_entry_hashes: compared,
        aud: FieldElement::from(RP_ID),
        nonce: FieldElement::from(NONCE),
        aat: has_aat.then(|| FlamingoAatClaims {
            trust_anchor_key_hash: from_hex(TRUST_ANCHOR_KEY_HASH),
            aat_flags: aat_flags(),
        }),
        compare_sources: COMPARE_SOURCES,
        engine_config_hash: from_hex(ENGINE_CONFIG_HASH),
        billing_nullifier,
    }
    .digest()
}

/// The WIP-107 billing nullifier and unblinded OPRF output of the World ID at `leaf_index` for
/// `rp_id`, from a real OPRF evaluation: blind the query, multiply by the key, unblind.
fn billing(leaf_index: u64, rp_id: u64) -> (FieldElement, [FieldElement; 2]) {
    let query = oprf_query_digest(leaf_index, BILLING_ACTION.into(), rp_id.into());
    let beta = || BlindingFactor::from_scalar(BLINDING_FACTOR.into()).unwrap();
    let blinded = client::blind_query(*query, beta()).blinded_query();
    let response =
        BlindedOprfResponse::new((blinded * ark_babyjubjub::Fr::from(OPRF_KEY)).into_affine());
    let prepared = beta().prepare();
    let output = response.unblind_response(&prepared);
    assert!(output.is_on_curve() && output.is_in_correct_subgroup_assuming_on_curve());
    let nullifier = FieldElement::from(client::finalize_query(
        *query,
        &response,
        &prepared,
        *ds::OPRF_PROOF.as_field_element(),
    ));
    let output = [FieldElement::from(output.x), FieldElement::from(output.y)];
    // Constraint 7 recomputes the nullifier this way; it must agree with the OPRF library.
    assert_eq!(
        poseidon::hash(ds::OPRF_PROOF, [query, output[0], output[1]]),
        nullifier
    );
    (nullifier, output)
}

/// The account's authorization message for a Flamingo Token digest and the RP's signal.
fn authorization_message(
    digest: FieldElement,
    verifier_key: &EdDSAPublicKey,
    signal_hash: FieldElement,
) -> FieldElement {
    poseidon::hash(
        ds::EMBEDDING_SIMILARITY_AUTH,
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

const TOML_HEADER: &str = "\
# Prover.toml for the WIP-202 Proof of Embedding Similarity circuit.
#
# GENERATED FILE. Do not edit by hand; regenerate with:
#   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity

";

/// The circuit's `main` inputs as `Prover.toml`; scalars precede tables, as TOML requires.
#[derive(Serialize)]
struct ProverToml {
    now: String,
    rp_id: String,
    nonce: String,
    has_aat: bool,
    trust_anchor_key_hash: String,
    platform: String,
    sec_level: String,
    sec_meta: String,
    authenticator_meta: String,
    engine_config_hash: String,
    challenge_hash: String,
    signal_hash: String,
    merkle_root: String,
    issuer_schema_id: String,
    issuer_version: String,
    genesis_issued_at_min: String,
    expires_at_min: String,
    session_id: String,
    flamingo_verifier_key: PublicKey,
    cred_pk: PublicKey,
    inputs: PrivateInputs,
}

#[derive(Serialize)]
struct PrivateInputs {
    session_id_r: String,
    billing_action: String,
    billing_oprf_output: Vec<String>,
    token: TokenInputs,
    account: AccountInputs,
    credential: CredentialInputs,
    hashes_json: HashesJsonInputs,
}

#[derive(Serialize)]
struct TokenInputs {
    live_capture_hash: String,
    billing_nullifier: String,
    sig: Signature,
}

#[derive(Serialize)]
struct AccountInputs {
    pk_index: String,
    leaf_index: String,
    siblings: Vec<String>,
    sig: Signature,
    user_pk: Vec<PublicKey>,
}

#[derive(Serialize)]
struct CredentialInputs {
    claims: Vec<String>,
    associated_data_hash: String,
    genesis_issued_at: String,
    expires_at: String,
    sub_blinding_factor: String,
    id: String,
    sig: Signature,
}

#[derive(Serialize)]
struct HashesJsonInputs {
    chunks: Vec<String>,
    len: String,
    digest_offset: String,
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
    // The helper builds the path of leaf 1, so `LEAF_INDEX` must be that leaf.
    assert!(
        MerkleInclusionProof::<TREE_DEPTH>::new(merkle_root, LEAF_INDEX, siblings)
            .is_valid(key_set.leaf_hash().into())
    );

    let compared = compared();
    let (hashes_json, digest_offset) = hashes_json();

    let zero = FieldElement::ZERO;
    let digest = token_digest(true, NOW, compared, zero);
    let digest_no_aat = token_digest(false, NOW, compared, zero);
    // Signed when the Credential expires, so only the validity check rejects it.
    let digest_at_expiry = token_digest(true, EXPIRES_AT, compared, zero);
    // Billed: this World ID's nullifier, and ones of another World ID and of another RP that
    // the Verifier also signed.
    let (billing_nullifier_own, billing_oprf_output) = billing(LEAF_INDEX, RP_ID);
    let (billing_nullifier_other, _) = billing(LEAF_INDEX + 1, RP_ID);
    let (billing_nullifier_other_rp, _) = billing(LEAF_INDEX, RP_ID + 1);
    let digest_billed = token_digest(true, NOW, compared, billing_nullifier_own);
    let digest_billed_other = token_digest(true, NOW, compared, billing_nullifier_other);
    let digest_billed_other_rp = token_digest(true, NOW, compared, billing_nullifier_other_rp);
    let token_billed = verifier_sk.sign(*digest_billed);
    let token_billed_other = verifier_sk.sign(*digest_billed_other);
    let token_billed_other_rp = verifier_sk.sign(*digest_billed_other_rp);
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
    let auth_billed = authenticator_sk.sign(*authorization_message(
        digest_billed,
        &verifier_key,
        signal_hash,
    ));
    let auth_billed_other = authenticator_sk.sign(*authorization_message(
        digest_billed_other,
        &verifier_key,
        signal_hash,
    ));
    let auth_billed_other_rp = authenticator_sk.sign(*authorization_message(
        digest_billed_other_rp,
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

    let chunks_type = format!("[Field; {CHUNK_SLOTS}]");
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
        ("HASHES_JSON_CHUNKS", &chunks_type, chunk_list.clone()),
        ("HASHES_JSON_LEN", "u32", hashes_json.len().to_string()),
        ("DIGEST_OFFSET", "u32", digest_offset.to_string()),
        ("SESSION_ID_R", "Field", dec(*session_id_r)),
        // Signed variants for the tests
        ("TOKEN_SIG_NO_AAT", "Signature", noir_sig(&token_no_aat)),
        ("AUTH_SIG_NO_AAT", "Signature", noir_sig(&auth_no_aat)),
        ("AUTH_SIG_NO_SIGNAL", "Signature", noir_sig(&auth_no_signal)),
        ("TOKEN_SIG_AT_EXPIRY", "Signature", noir_sig(&token_at_expiry)),
        ("AUTH_SIG_AT_EXPIRY", "Signature", noir_sig(&auth_at_expiry)),
        ("BILLING_NULLIFIER", "Field", dec(*billing_nullifier_own)),
        ("BILLING_ACTION", "Field", BILLING_ACTION.to_string()),
        ("BILLING_OPRF_OUTPUT", "[Field; 2]", list(billing_oprf_output.map(|v| dec(*v)))),
        ("TOKEN_SIG_BILLED", "Signature", noir_sig(&token_billed)),
        ("AUTH_SIG_BILLED", "Signature", noir_sig(&auth_billed)),
        ("BILLING_NULLIFIER_OTHER_LEAF", "Field", dec(*billing_nullifier_other)),
        ("TOKEN_SIG_BILLED_OTHER_LEAF", "Signature", noir_sig(&token_billed_other)),
        ("AUTH_SIG_BILLED_OTHER_LEAF", "Signature", noir_sig(&auth_billed_other)),
        ("BILLING_NULLIFIER_OTHER_RP", "Field", dec(*billing_nullifier_other_rp)),
        ("TOKEN_SIG_BILLED_OTHER_RP", "Signature", noir_sig(&token_billed_other_rp)),
        ("AUTH_SIG_BILLED_OTHER_RP", "Signature", noir_sig(&auth_billed_other_rp)),
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

    let identity = || PublicKey {
        x: "0".into(),
        y: "1".into(),
    };
    let mut claims = vec!["0".to_string(); Credential::MAX_CLAIMS];
    claims[0] = claim_0;
    let prover_toml = ProverToml {
        now: NOW.to_string(),
        rp_id: RP_ID.to_string(),
        nonce: NONCE.to_string(),
        has_aat: true,
        trust_anchor_key_hash: takh,
        platform: PLATFORM.to_string(),
        sec_level: SEC_LEVEL.to_string(),
        sec_meta: SEC_META.to_string(),
        authenticator_meta: AUTHENTICATOR_META.to_string(),
        engine_config_hash,
        challenge_hash: dec(*compared[2]),
        signal_hash: dec(*signal_hash),
        merkle_root: dec(*merkle_root),
        issuer_schema_id: ISSUER_SCHEMA_ID.to_string(),
        issuer_version: ISSUER_VERSION.to_string(),
        genesis_issued_at_min: GENESIS_ISSUED_AT_MIN.to_string(),
        expires_at_min: EXPIRES_AT_MIN.to_string(),
        session_id: dec(*session_id),
        flamingo_verifier_key: (&verifier_key).into(),
        cred_pk: (&credential.issuer).into(),
        inputs: PrivateInputs {
            session_id_r: dec(*session_id_r),
            billing_action: "0".into(),
            billing_oprf_output: vec!["0".into(), "0".into()],
            token: TokenInputs {
                live_capture_hash: dec(*compared[1]),
                billing_nullifier: "0".into(),
                sig: (&token).into(),
            },
            account: AccountInputs {
                pk_index: "0".into(),
                leaf_index: LEAF_INDEX.to_string(),
                siblings: siblings.iter().map(|s| dec(**s)).collect(),
                sig: (&auth).into(),
                user_pk: std::iter::once((&authenticator_sk.public()).into())
                    .chain(std::iter::repeat_with(identity).take(6))
                    .collect(),
            },
            credential: CredentialInputs {
                claims,
                associated_data_hash: "0".into(),
                genesis_issued_at: GENESIS_ISSUED_AT.to_string(),
                expires_at: EXPIRES_AT.to_string(),
                sub_blinding_factor: dec(*sub_blinding_factor),
                id: CRED_ID.to_string(),
                sig: cred_sig.into(),
            },
            hashes_json: HashesJsonInputs {
                chunks: chunks(&hashes_json).iter().map(|c| dec(**c)).collect(),
                len: hashes_json.len().to_string(),
                digest_offset: digest_offset.to_string(),
            },
        },
    };
    let toml = format!(
        "{TOML_HEADER}{}",
        toml::to_string_pretty(&prover_toml).expect("fixture serializes to TOML")
    );

    Rendered { toml, noir }
}

/// Ignores whitespace and trailing commas, which `nargo fmt` changes in the generated Noir file.
fn normalized(source: &str) -> String {
    source
        .split_whitespace()
        .collect::<String>()
        .replace(",]", "]")
        .replace(",}", "}")
}

#[test]
fn fixtures_match_the_generator() {
    let rendered = render();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("noir/embedding-similarity");
    for (file, content) in [
        ("Prover.toml", &rendered.toml),
        ("src/test_fixtures.nr", &rendered.noir),
    ] {
        let path = dir.join(file);
        if env::var_os("UPDATE_PROVER_TOML").is_some() {
            fs::write(&path, content)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            continue;
        }
        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert_eq!(
            normalized(&committed),
            normalized(content),
            "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p \
             world-id-proof embedding_similarity` (and re-run `nargo fmt`)",
            path.display()
        );
    }
}

/// Pins the `hashes.json` bounds to WIP-202: the spec's constants and its chunk count
/// `⌈MAX_HASHES_JSON_BYTES / 31⌉`, so the circuit cannot drift from what a prover built from the
/// spec passes.
#[test]
fn hashes_json_bounds_match_the_spec() {
    let spec = include_str!("../../../docs/WIPs/wip-202.md");
    let row = spec
        .lines()
        .find(|line| line.starts_with("| `MIN_HASHES_JSON_BYTES`, `MAX_HASHES_JSON_BYTES` |"))
        .expect("WIP-202 defines the hashes.json bounds");
    let values: Vec<usize> = row
        .split('|')
        .nth(2)
        .unwrap()
        .split(',')
        .map(|v| v.trim().trim_matches('`').parse().unwrap())
        .collect();
    assert_eq!(values[1], MAX_HASHES_JSON_BYTES);
    assert!(spec.contains("| `hashes_json` | [Field element; ⌈`MAX_HASHES_JSON_BYTES` / 31⌉] |"));
    assert_eq!(CHUNK_SLOTS, MAX_HASHES_JSON_BYTES.div_ceil(31));
}

/// Pins every circuit constant the Rust side repeats to its Noir definition.
#[test]
fn circuit_constants_match_the_noir_constants() {
    let constants = include_str!("../noir/embedding-similarity/src/constants.nr");
    let global = |name: &str| -> usize {
        let line = constants
            .lines()
            .find(|line| line.starts_with(&format!("pub global {name}: u32 = ")))
            .unwrap_or_else(|| panic!("{name} missing from constants.nr"));
        line.rsplit("= ")
            .next()
            .unwrap()
            .trim_end_matches(';')
            .parse()
            .unwrap()
    };
    assert_eq!(global("MIN_HASHES_JSON_BYTES"), MIN_HASHES_JSON_BYTES);
    assert_eq!(global("MAX_HASHES_JSON_BYTES"), MAX_HASHES_JSON_BYTES);
    assert_eq!(global("COMPARE_SOURCES"), COMPARE_SOURCES as usize);
    assert_eq!(global("CLAIM_INDEX"), CLAIM_INDEX);
    assert_eq!(global("DIGEST_HEX_LEN"), DIGEST_HEX_LEN);
    // A Noir string literal escapes quotes like Rust's `Debug` of a `str`.
    let thumbnail_key = std::str::from_utf8(THUMBNAIL_KEY).unwrap();
    assert!(constants.contains(&format!(
        "pub global THUMBNAIL_KEY: [u8; {}] = {thumbnail_key:?}.as_bytes();",
        THUMBNAIL_KEY.len()
    )));
    let var_hash = include_str!("../noir/world-id-components/src/var_hash.nr");
    assert!(var_hash.contains(&format!("pub global CHUNK_BYTES: u32 = {CHUNK_BYTES};")));
}

/// The fixture's Flamingo Tokens are the WIP-201 Appendix A1 test vectors.
#[test]
fn token_digests_match_the_wip_201_vectors() {
    let zero = FieldElement::ZERO;
    assert_eq!(
        token_digest(true, NOW, compared(), zero),
        from_hex(DIGEST_WITH_AAT)
    );
    assert_eq!(
        token_digest(false, NOW, compared(), zero),
        from_hex(DIGEST_WITHOUT_AAT)
    );
    assert_eq!(
        token_digest(true, NOW, compared(), FieldElement::from(7_u64)),
        from_hex(DIGEST_BILLED_7)
    );
    assert_eq!(aat_flags(), 0x00a3_0000_0000_0102);
}

/// Pins the domain separators to the integers hardcoded in the Noir package.
#[test]
fn domain_separators_match_the_noir_constants() {
    let as_int = |tag: &[u8]| dec(ark_babyjubjub::Fq::from_be_bytes_mod_order(tag));
    assert_eq!(
        dec(*DS_SIGN.as_field_element()),
        "127603488023523044162070750169730750022280897185614"
    );
    assert_eq!(
        as_int(b"WORLD-ID/WIP-202/AUTH"),
        "127603488023523044162070750169730750023380107613256"
    );
    assert_eq!(
        as_int(b"World ID Query"),
        "1773399373884719043551600379785849"
    );
    assert_eq!(
        as_int(b"World ID Proof"),
        "1773399373884719043551596035141478"
    );
}

// Deterministic test keys, not real key material. The Verifier key is WIP-201's.
fn authenticator_sk() -> EdDSAPrivateKey {
    EdDSAPrivateKey::from_bytes([42_u8; 32])
}

fn issuer_sk() -> EdDSAPrivateKey {
    EdDSAPrivateKey::from_bytes([13_u8; 32])
}

fn verifier_sk() -> EdDSAPrivateKey {
    EdDSAPrivateKey::from_bytes([0x15_u8; 32])
}

/// A field element whose most significant byte is `prefix`.
fn prefixed(prefix: OprfPrefix, n: u64) -> FieldElement {
    FieldElement::try_from(U256::from(n) | (U256::from(prefix as u8) << 248)).unwrap()
}

/// The RP's WIP-202 request behind the fixture, for the World ID's session with blinding factor
/// `session_id_r`. Its signature is a placeholder: no check in this crate verifies it.
pub(crate) fn embedding_similarity_request(session_id_r: FieldElement) -> ProofRequest {
    let session = SessionId::new(
        poseidon::hash(
            ds::SESSION_COMMITMENT,
            [FieldElement::from(LEAF_INDEX), session_id_r],
        ),
        prefixed(OprfPrefix::SessionOprfSeed, 1),
    )
    .unwrap();
    ProofRequest {
        id: "req_wip_202".into(),
        version: RequestVersion::V1,
        proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
            action: prefixed(OprfPrefix::EmbeddingSimilarity, 1),
            challenge_hash: sha256_field(CHALLENGE_IMAGE),
            aat: None,
        }),
        session_id: SessionRef::Existing(session),
        created_at: u64::from(NOW) - 60,
        expires_at: u64::from(NOW) + 240,
        rp_id: RpId::new(RP_ID),
        oprf_key_id: OprfKeyId::new(U160::from(RP_ID)),
        signature: alloy_primitives::Signature::test_signature(),
        nonce: FieldElement::from(NONCE),
        requests: vec![RequestItem::embedding_similarity(
            "poh".into(),
            Some(SIGNAL.to_vec()),
            Some(GENESIS_ISSUED_AT_MIN),
            Some(u64::from(EXPIRES_AT_MIN)),
        )],
        constraints: None,
    }
}

/// The committed `Prover.toml` witness as a typed circuit input: unbilled, with an AAT.
pub(crate) fn embedding_similarity_fixture() -> EmbeddingSimilarityCircuitInput<TREE_DEPTH> {
    let authenticator_sk = authenticator_sk();
    let issuer_sk = issuer_sk();
    let key_set = AuthenticatorPublicKeySet::new(vec![authenticator_sk.public()]).unwrap();
    let (siblings, merkle_root) = first_leaf_merkle_path(key_set.leaf_hash());
    let compared = compared();
    let (hashes_json, _) = hashes_json();

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
    let session_id_r = FieldElement::from(555_u64);

    let mut input = EmbeddingSimilarityCircuitInput {
        request: EmbeddingSimilarityRequestInputs::from_request(
            &embedding_similarity_request(session_id_r),
            ISSUER_VERSION,
        )
        .unwrap(),
        now: NOW,
        flamingo_verifier_key: verifier_sk().public(),
        engine_config_hash: from_hex(ENGINE_CONFIG_HASH),
        aat: Some(AatPublicValues {
            trust_anchor_key_hash: from_hex(TRUST_ANCHOR_KEY_HASH),
            platform: PLATFORM,
            sec_level: SEC_LEVEL,
            sec_meta: SEC_META,
            authenticator_meta: AUTHENTICATOR_META,
        }),
        cred_pk: credential.issuer.clone(),
        live_capture_hash: compared[1],
        billing_nullifier: FieldElement::ZERO,
        token_signature: credential.signature.clone().unwrap(),
        key_index: 0,
        key_set,
        inclusion_proof: MerkleInclusionProof::new(merkle_root, LEAF_INDEX, siblings),
        signature: credential.signature.clone().unwrap(),
        claims: credential.claims.clone().try_into().unwrap(),
        associated_data_hash: credential.associated_data_commitment,
        genesis_issued_at: GENESIS_ISSUED_AT,
        expires_at: u64::from(EXPIRES_AT),
        sub_blinding_factor,
        credential_id: CRED_ID,
        credential_signature: credential.signature.clone().unwrap(),
        hashes_json,
        session_id_r,
        billing_action: FieldElement::ZERO,
        billing_oprf_output: [FieldElement::ZERO; 2],
    };
    resign(&mut input);
    input
}

/// [`embedding_similarity_fixture`] for an RP that bills this World ID.
pub(crate) fn embedding_similarity_billed_fixture() -> EmbeddingSimilarityCircuitInput<TREE_DEPTH> {
    let mut input = embedding_similarity_fixture();
    let (billing_nullifier, billing_oprf_output) = billing(LEAF_INDEX, RP_ID);
    input.billing_nullifier = billing_nullifier;
    input.billing_action = FieldElement::from(BILLING_ACTION);
    input.billing_oprf_output = billing_oprf_output;
    resign(&mut input);
    input
}

/// Re-signs the Credential, the Flamingo Token and the authorization after a test changed them.
pub(crate) fn resign(input: &mut EmbeddingSimilarityCircuitInput<TREE_DEPTH>) {
    let request = &input.request;
    let credential = Credential::new()
        .id(input.credential_id)
        .issuer_version(request.issuer_version)
        .issuer_schema_id(request.issuer_schema_id)
        .subject(Credential::compute_sub(
            input.inclusion_proof.leaf_index,
            input.sub_blinding_factor,
        ))
        .genesis_issued_at(input.genesis_issued_at)
        .expires_at(input.expires_at);
    let credential = Credential {
        claims: input.claims.to_vec(),
        associated_data_commitment: input.associated_data_hash,
        ..credential
    }
    .sign(&issuer_sk())
    .unwrap();
    input.credential_signature = credential.signature.unwrap();
    input.cred_pk = credential.issuer;

    let (_, digest_offset) = hashes_json();
    let thumbnail = std::str::from_utf8(&input.hashes_json[digest_offset..digest_offset + 64])
        .map(from_hex)
        .unwrap_or(FieldElement::ZERO);
    let request = &input.request;
    let digest = FlamingoClaims {
        now: input.now,
        compared_entry_hashes: [
            thumbnail,
            input.live_capture_hash,
            request.challenge_hash,
            FieldElement::ZERO,
        ],
        aud: request.rp_id,
        nonce: request.nonce,
        aat: input.aat.as_ref().map(|aat| FlamingoAatClaims {
            trust_anchor_key_hash: aat.trust_anchor_key_hash,
            aat_flags: u64::from(aat.platform)
                + (u64::from(aat.sec_level) << 8)
                + (u64::from(aat.sec_meta) << 48)
                + (u64::from(aat.authenticator_meta) << 52),
        }),
        compare_sources: COMPARE_SOURCES,
        engine_config_hash: input.engine_config_hash,
        billing_nullifier: input.billing_nullifier,
    }
    .digest();
    input.token_signature = verifier_sk().sign(*digest);
    input.signature = authenticator_sk().sign(*authorization_message(
        digest,
        &input.flamingo_verifier_key,
        request.signal_hash,
    ));
}

/// A witness or `Prover.toml` value tree, so the two can be compared without the circuit ABI.
#[derive(Debug, PartialEq, Eq)]
enum Witness {
    Value(String),
    List(Vec<Self>),
    Table(BTreeMap<String, Self>),
}

impl Witness {
    fn from_input(value: &InputValue) -> Self {
        match value {
            InputValue::Field(element) => Self::Value(element.into_repr().to_string()),
            InputValue::Vec(values) => Self::List(values.iter().map(Self::from_input).collect()),
            InputValue::Struct(fields) => Self::Table(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::from_input(value)))
                    .collect(),
            ),
            other => panic!("unexpected witness value {other:?}"),
        }
    }

    fn from_input_map(map: &InputMap) -> Self {
        Self::Table(
            map.iter()
                .map(|(key, value)| (key.clone(), Self::from_input(value)))
                .collect(),
        )
    }

    /// Booleans are field elements in the witness.
    fn from_toml(value: &toml::Value) -> Self {
        match value {
            toml::Value::String(s) => Self::Value(s.clone()),
            toml::Value::Integer(i) => Self::Value(i.to_string()),
            toml::Value::Boolean(b) => Self::Value(u8::from(*b).to_string()),
            toml::Value::Array(values) => Self::List(values.iter().map(Self::from_toml).collect()),
            toml::Value::Table(fields) => Self::Table(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::from_toml(value)))
                    .collect(),
            ),
            other => panic!("unexpected Prover.toml value {other:?}"),
        }
    }
}

#[test]
fn witness_matches_the_prover_toml() {
    let committed: toml::Value =
        toml::from_str(include_str!("../noir/embedding-similarity/Prover.toml")).unwrap();
    let witness = embedding_similarity_fixture().into_witness().unwrap();
    assert_eq!(
        Witness::from_input_map(&witness),
        Witness::from_toml(&committed)
    );
}
