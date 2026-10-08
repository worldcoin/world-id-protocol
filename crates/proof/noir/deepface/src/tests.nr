use crate::{
    constants::{CHUNK_SLOTS, MAX_CLAIMS, MERKLE_DEPTH, NUM_KEYS},
    hashes_json::{claims_hash_v1, thumbnail_digest},
    main,
    test_fixtures::{
        AAT_BLIND, AAT_EXP, AAT_SIG_R, AAT_SIG_S, ASSURANCE_LEVEL, ASSURANCE_LEVEL_MIN, AUD,
        AUTH_SIG_R, AUTH_SIG_S, AUTHENTICATOR_PROVIDER_KEY, AUTHENTICATOR_PROVIDER_KEY_HASH,
        CHALLENGE_HASH, CLAIM_0, COMPARED_ENTRY_HASH, COMPARISON_AGE_MAX, CRED_ID, CRED_PK,
        CRED_SIG_R, CRED_SIG_S, EXPIRES_AT, FUTURE_IAT, GENESIS_ISSUED_AT, GENESIS_ISSUED_AT_MIN,
        HASHES_JSON_CHUNKS, HASHES_JSON_LEN, IAT, ISSUER_SCHEMA_ID, ISSUER_VERSION, LEAF_INDEX,
        MERKLE_ROOT, METHOD, MIN_BUILD_VERSION, NONCE, NOW, PLATFORM, REQUEST_HASH, SEC_FLAGS,
        SEC_LEVEL, SEC_META, SESSION_ID, SESSION_ID_R, SIBLINGS, SUB_BLINDING_FACTOR,
        THUMBNAIL_OFFSET, TOKEN_SIG_R, TOKEN_SIG_R_FUTURE_IAT, TOKEN_SIG_R_LOW_LEVEL,
        TOKEN_SIG_R_TWO_WAY, TOKEN_SIG_S, TOKEN_SIG_S_FUTURE_IAT, TOKEN_SIG_S_LOW_LEVEL,
        TOKEN_SIG_S_TWO_WAY, USER_PK, USER_PRESENCE, VERIFIER_KEY,
    },
    types::{
        CredentialInputs, HashesJsonInputs, PrivateInputs, PublicKey, RegistryInputs,
        VerifierTokenInputs,
    },
};
use authenticator_assertion::AuthenticatorAssertionPrivateInputs;

struct Public {
    method: Field,
    assurance_level_min: Field,
    comparison_age_max: Field,
    challenge_hash: Field,
    now: Field,
    authenticator_provider_key_hash: Field,
    platform: u8,
    user_presence: u8,
    min_build_version: u32,
}

fn public() -> Public {
    Public {
        method: METHOD,
        assurance_level_min: ASSURANCE_LEVEL_MIN,
        comparison_age_max: COMPARISON_AGE_MAX,
        challenge_hash: CHALLENGE_HASH,
        now: NOW,
        authenticator_provider_key_hash: AUTHENTICATOR_PROVIDER_KEY_HASH,
        platform: PLATFORM,
        user_presence: USER_PRESENCE,
        min_build_version: MIN_BUILD_VERSION,
    }
}

fn inputs() -> PrivateInputs {
    let mut user_pk = [PublicKey { x: 0, y: 1 }; NUM_KEYS];
    user_pk[0] = USER_PK;
    let mut claims = [0; MAX_CLAIMS];
    claims[0] = CLAIM_0;
    PrivateInputs {
        registry: RegistryInputs {
            user_pk,
            pk_index: 0,
            sig_s: AUTH_SIG_S,
            sig_r: AUTH_SIG_R,
            leaf_index: LEAF_INDEX,
            siblings: SIBLINGS,
        },
        credential: CredentialInputs {
            claims,
            associated_data_hash: 0,
            genesis_issued_at: GENESIS_ISSUED_AT,
            expires_at: EXPIRES_AT,
            sub_blinding_factor: SUB_BLINDING_FACTOR,
            id: CRED_ID,
            sig_s: CRED_SIG_S,
            sig_r: CRED_SIG_R,
        },
        token: VerifierTokenInputs {
            iat: IAT,
            method: METHOD,
            assurance_level: ASSURANCE_LEVEL,
            request_hash: REQUEST_HASH,
            compared_entry_hash: COMPARED_ENTRY_HASH,
            sig_s: TOKEN_SIG_S,
            sig_r: TOKEN_SIG_R,
        },
        aat: AuthenticatorAssertionPrivateInputs {
            authenticator_provider_key: AUTHENTICATOR_PROVIDER_KEY,
            exp: AAT_EXP,
            sec_flags: SEC_FLAGS,
            sig_s: AAT_SIG_S,
            sig_r: AAT_SIG_R,
            cdh: REQUEST_HASH,
            blind: AAT_BLIND,
        },
        hashes_json: HashesJsonInputs {
            chunks: HASHES_JSON_CHUNKS,
            len: HASHES_JSON_LEN,
            thumbnail_offset: THUMBNAIL_OFFSET,
        },
        session_id_r: SESSION_ID_R,
    }
}

fn prove(p: Public, inputs: PrivateInputs) {
    main(
        VERIFIER_KEY,
        p.method,
        p.assurance_level_min,
        p.comparison_age_max,
        p.challenge_hash,
        p.now,
        p.authenticator_provider_key_hash,
        AUD,
        NONCE,
        p.platform,
        SEC_LEVEL,
        SEC_META,
        p.user_presence,
        p.min_build_version,
        MERKLE_ROOT,
        ISSUER_SCHEMA_ID,
        ISSUER_VERSION,
        CRED_PK,
        GENESIS_ISSUED_AT_MIN,
        SESSION_ID,
        inputs,
    );
}

#[test]
fn test_accepts_the_fixture() {
    prove(public(), inputs());
}

#[test]
fn test_accepts_the_two_way_flow() {
    let mut p = public();
    p.challenge_hash = 0;
    let mut i = inputs();
    i.token.compared_entry_hash[2] = 0;
    i.token.sig_s = TOKEN_SIG_S_TWO_WAY;
    i.token.sig_r = TOKEN_SIG_R_TWO_WAY;
    prove(p, i);
}

#[test(should_fail_with = "invalid verifier token signature")]
fn test_rejects_a_tampered_token() {
    let mut i = inputs();
    i.token.compared_entry_hash[1] += 1;
    prove(public(), i);
}

#[test(should_fail_with = "unexpected method")]
fn test_rejects_another_method() {
    let mut p = public();
    p.method = METHOD + 1;
    prove(p, inputs());
}

#[test(should_fail_with = "assurance level below minimum")]
fn test_rejects_a_lower_assurance_level() {
    let mut i = inputs();
    i.token.assurance_level = 1;
    i.token.sig_s = TOKEN_SIG_S_LOW_LEVEL;
    i.token.sig_r = TOKEN_SIG_R_LOW_LEVEL;
    prove(public(), i);
}

#[test(should_fail_with = "comparison must not be future-dated")]
fn test_rejects_a_future_comparison() {
    let mut i = inputs();
    i.token.iat = FUTURE_IAT;
    i.token.sig_s = TOKEN_SIG_S_FUTURE_IAT;
    i.token.sig_r = TOKEN_SIG_R_FUTURE_IAT;
    prove(public(), i);
}

#[test(should_fail_with = "comparison too old")]
fn test_rejects_an_old_comparison() {
    let mut p = public();
    p.comparison_age_max = 30;
    prove(p, inputs());
}

#[test(should_fail_with = "challenge mismatch")]
fn test_rejects_another_challenge() {
    let mut p = public();
    p.challenge_hash += 1;
    prove(p, inputs());
}

#[test(should_fail_with = "thumbnail key mismatch")]
fn test_rejects_an_entry_other_than_the_thumbnail() {
    let mut i = inputs();
    // Point at the `face.png` entry, which also starts a key.
    i.hashes_json.thumbnail_offset = 1;
    prove(public(), i);
}

#[test(should_fail_with = "thumbnail entry must start a key")]
fn test_rejects_a_shifted_thumbnail_offset() {
    let mut i = inputs();
    i.hashes_json.thumbnail_offset -= 1;
    prove(public(), i);
}

#[test(should_fail_with = "hashes.json does not match the credential claim")]
fn test_rejects_a_tampered_hashes_json() {
    let mut i = inputs();
    // Chunk 0 lies outside the thumbnail window, so only the claim check catches it.
    i.hashes_json.chunks[0] += 1;
    prove(public(), i);
}

#[test(should_fail_with = "chunk past the end must be zero")]
fn test_rejects_a_chunk_past_the_end() {
    let mut i = inputs();
    i.hashes_json.chunks[CHUNK_SLOTS - 1] = 1;
    prove(public(), i);
}

#[test(should_fail_with = "invalid signature")]
fn test_rejects_an_aat_for_another_request() {
    let mut i = inputs();
    i.aat.blind += 1;
    prove(public(), i);
}

#[test(should_fail_with = "aat cdh does not match the request hash")]
fn test_rejects_an_aat_cdh_other_than_the_request_hash() {
    let mut i = inputs();
    i.aat.cdh += 1;
    prove(public(), i);
}

#[test(should_fail_with = "authenticator_provider_key does not match its hash")]
fn test_rejects_another_authenticator_provider() {
    let mut p = public();
    p.authenticator_provider_key_hash += 1;
    prove(p, inputs());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_rejects_another_platform() {
    let mut p = public();
    p.platform += 2;
    prove(p, inputs());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_rejects_another_user_presence() {
    let mut p = public();
    p.user_presence += 1;
    prove(p, inputs());
}

#[test(should_fail_with = "build_version below minimum")]
fn test_rejects_a_build_version_below_the_minimum() {
    let mut p = public();
    // The fixture's `build_version` equals `MIN_BUILD_VERSION`.
    p.min_build_version += 1;
    prove(p, inputs());
}

#[test(should_fail_with = "invalid authenticator signature")]
fn test_rejects_an_unauthorized_request() {
    let mut i = inputs();
    i.registry.sig_s += 1;
    prove(public(), i);
}

#[test(should_fail_with = "merkle proof verification failed")]
fn test_rejects_another_registry() {
    let mut i = inputs();
    i.registry.siblings[MERKLE_DEPTH - 1] += 1;
    prove(public(), i);
}

/// Packs `bytes` into sponge chunks: 31-byte big-endian integers, the last shorter.
fn chunks_of<let N: u32>(bytes: [u8; N]) -> [Field; CHUNK_SLOTS] {
    let mut chunks = [0; CHUNK_SLOTS];
    for i in 0..N {
        chunks[i / 31] = chunks[i / 31] * 256 + bytes[i] as Field;
    }
    chunks
}

#[test]
fn test_reads_a_thumbnail_in_the_final_short_chunk() {
    // 12 filler bytes put the entry across the boundary into a short final chunk.
    let json = "{\"a\":\"1234\",\"thumbnail.png\":\"00000000000000000000000000000000000000000000000000000000000000ff\"}"
        .as_bytes();
    let digest = thumbnail_digest(
        HashesJsonInputs { chunks: chunks_of(json), len: json.len(), thumbnail_offset: 12 },
    );
    assert_eq(digest, 255);
}

#[test(should_fail_with = "hashes.json is shorter than its bound")]
fn test_rejects_a_hashes_json_below_the_length_window() {
    let mut json = inputs().hashes_json;
    json.len = 3071;
    let _ = claims_hash_v1(json);
}
