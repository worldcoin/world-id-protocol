use crate::{
    constants::{CHUNK_SLOTS, MAX_CLAIMS, MERKLE_DEPTH, NUM_KEYS},
    hashes_json::{claims_hash_v1, thumbnail_digest},
    main,
    test_fixtures::{
        AUD, AUTH_SIG, AUTH_SIG_NO_AAT, AUTHENTICATOR_PROVIDER_KEY_HASH, CHALLENGE_HASH, CLAIM_0,
        COMPARED_ENTRY_HASH, CRED_ID, CRED_PK, CRED_SIG, ENGINE_CONFIG_HASH, EXPIRES_AT,
        FOURTH_ENTRY_HASH, GENESIS_ISSUED_AT, GENESIS_ISSUED_AT_MIN, HASHES_JSON_CHUNKS,
        HASHES_JSON_LEN, ISSUER_SCHEMA_ID, ISSUER_VERSION, LEAF_INDEX, MERKLE_ROOT,
        MIN_BUILD_VERSION, NONCE, NOW, PLATFORM, SEC_LEVEL, SEC_META, SESSION_ID, SESSION_ID_R,
        SIBLINGS, SUB_BLINDING_FACTOR, THUMBNAIL_OFFSET, TOKEN_SIG, TOKEN_SIG_FOURTH,
        TOKEN_SIG_NO_AAT, USER_PK, USER_PRESENCE, VERIFIER_KEY,
    },
    types::{
        AccountInputs, CredentialInputs, FlamingoTokenInputs, HashesJsonInputs, PrivateInputs,
        PublicKey,
    },
};

struct Public {
    now: u32,
    has_aat: bool,
    authenticator_provider_key_hash: Field,
    platform: u8,
    sec_level: u8,
    sec_meta: u8,
    user_presence: u8,
    min_build_version: u32,
    engine_config_hash: Field,
    challenge_hash: Field,
    genesis_issued_at_min: Field,
    session_id: Field,
}

fn public() -> Public {
    Public {
        now: NOW,
        has_aat: true,
        authenticator_provider_key_hash: AUTHENTICATOR_PROVIDER_KEY_HASH,
        platform: PLATFORM,
        sec_level: SEC_LEVEL,
        sec_meta: SEC_META,
        user_presence: USER_PRESENCE,
        min_build_version: MIN_BUILD_VERSION,
        engine_config_hash: ENGINE_CONFIG_HASH,
        challenge_hash: CHALLENGE_HASH,
        genesis_issued_at_min: GENESIS_ISSUED_AT_MIN,
        session_id: SESSION_ID,
    }
}

fn inputs() -> PrivateInputs {
    let mut user_pk = [PublicKey { x: 0, y: 1 }; NUM_KEYS];
    user_pk[0] = USER_PK;
    let mut claims = [0; MAX_CLAIMS];
    claims[0] = CLAIM_0;
    PrivateInputs {
        token: FlamingoTokenInputs { compared_entry_hash: COMPARED_ENTRY_HASH, sig: TOKEN_SIG },
        account: AccountInputs {
            user_pk,
            pk_index: 0,
            auth: AUTH_SIG,
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
            sig: CRED_SIG,
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
        p.now,
        AUD,
        NONCE,
        p.has_aat,
        p.authenticator_provider_key_hash,
        p.platform,
        p.sec_level,
        p.sec_meta,
        p.user_presence,
        p.min_build_version,
        p.engine_config_hash,
        p.challenge_hash,
        MERKLE_ROOT,
        ISSUER_SCHEMA_ID,
        ISSUER_VERSION,
        CRED_PK,
        p.genesis_issued_at_min,
        p.session_id,
        inputs,
    );
}

/// Public values of a Flamingo Token without an AAT; the AAT values are ignored.
fn public_without_aat() -> Public {
    let mut p = public();
    p.has_aat = false;
    p
}

fn inputs_without_aat() -> PrivateInputs {
    let mut i = inputs();
    i.token.sig = TOKEN_SIG_NO_AAT;
    i.account.auth = AUTH_SIG_NO_AAT;
    i
}

#[test]
fn test_accepts_the_fixture() {
    prove(public(), inputs());
}

#[test]
fn test_accepts_a_token_without_an_aat() {
    prove(public_without_aat(), inputs_without_aat());
}

#[test]
fn test_accepts_a_nil_session() {
    let mut p = public();
    p.session_id = 0;
    prove(p, inputs());
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_a_token_without_an_aat_as_one_with_an_aat() {
    prove(public(), inputs_without_aat());
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_a_tampered_live_entry() {
    let mut i = inputs();
    i.token.compared_entry_hash[1] += 1;
    prove(public(), i);
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_engine_config() {
    let mut p = public();
    p.engine_config_hash += 1;
    prove(p, inputs());
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_min_build_version() {
    let mut p = public();
    p.min_build_version += 1;
    prove(p, inputs());
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_now_with_an_aat() {
    let mut p = public();
    p.now -= 1;
    prove(p, inputs());
}

#[test(should_fail_with = "sec_meta exceeds 3 bits")]
fn test_rejects_a_wide_sec_meta() {
    let mut p = public();
    p.sec_meta = 8;
    prove(p, inputs());
}

#[test(should_fail_with = "challenge_hash must not be zero")]
fn test_rejects_a_zero_challenge() {
    let mut p = public();
    p.challenge_hash = 0;
    prove(p, inputs());
}

#[test(should_fail_with = "challenge mismatch")]
fn test_rejects_another_challenge() {
    let mut p = public();
    p.challenge_hash += 1;
    prove(p, inputs());
}

#[test(should_fail_with = "unexpected fourth compared entry")]
fn test_rejects_a_fourth_compared_entry() {
    let mut i = inputs();
    i.token.compared_entry_hash[3] = FOURTH_ENTRY_HASH;
    i.token.sig = TOKEN_SIG_FOURTH;
    prove(public(), i);
}

#[test(should_fail_with = "thumbnail key mismatch")]
fn test_rejects_an_entry_other_than_the_thumbnail() {
    let mut i = inputs();
    // Point at the first entry, which also starts a key.
    i.hashes_json.thumbnail_offset = 1;
    prove(public(), i);
}

#[test(should_fail_with = "thumbnail entry must start a key")]
fn test_rejects_a_shifted_thumbnail_offset() {
    let mut i = inputs();
    i.hashes_json.thumbnail_offset -= 1;
    prove(public(), i);
}

#[test(should_fail_with = "pk_index out of range")]
fn test_rejects_a_key_index_past_the_slots() {
    let mut i = inputs();
    i.account.pk_index = 7;
    prove(public(), i);
}

#[test(should_fail_with = "Public key cannot be identity")]
fn test_rejects_an_inactive_key_slot() {
    let mut i = inputs();
    i.account.pk_index = 1;
    prove(public(), i);
}

#[test(should_fail_with = "merkle proof verification failed")]
fn test_rejects_another_registry() {
    let mut i = inputs();
    i.account.siblings[MERKLE_DEPTH - 1] += 1;
    prove(public(), i);
}

#[test(should_fail_with = "invalid authorization signature")]
fn test_rejects_an_unauthorized_result() {
    // A valid authorization of the token without an AAT does not cover the one with.
    let mut i = inputs();
    i.account.auth = AUTH_SIG_NO_AAT;
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

#[test(should_fail_with = "invalid credential signature")]
fn test_rejects_a_credential_of_another_account() {
    let mut i = inputs();
    i.credential.sub_blinding_factor += 1;
    prove(public(), i);
}

#[test(should_fail_with = "credential expired")]
fn test_rejects_an_expired_credential() {
    let mut p = public_without_aat();
    p.now = 1900000000;
    prove(p, inputs_without_aat());
}

#[test(should_fail_with = "credential too recent")]
fn test_rejects_a_credential_issued_after_the_minimum() {
    let mut p = public();
    p.genesis_issued_at_min = GENESIS_ISSUED_AT + 1;
    prove(p, inputs());
}

#[test(should_fail_with = "session_id must be nil or the session commitment")]
fn test_rejects_another_session() {
    let mut p = public();
    p.session_id += 1;
    prove(p, inputs());
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
