// Constraint tests for the WIP-111 Embedding Similarity circuit. Signatures
// cannot be produced in-circuit, so all signed values come from the generated
// fixture (`test_fixtures.nr`); constraint numbers refer to WIP-111 section 3.5.
use super::main;
use super::test_fixtures as fx;
use super::types::{PrivateInputs, PublicKey};

/// Every public input of `main`, so a test can tweak exactly one.
struct Publics {
    trust_anchor_key: PublicKey,
    authenticator_meta: Field,
    nonce: Field,
    rp_id: Field,
    now: Field,
    session_id: Field,
    genesis_issued_at_min: Field,
    verifier_key: PublicKey,
    challenge_commitment: Field,
    comparison_age_max: Field,
    similarity_min: Field,
    merkle_root: Field,
    issuer_schema_id: Field,
    cred_pk: PublicKey,
    issuer_version: Field,
    claim_index: Field,
}

fn fixture_publics() -> Publics {
    Publics {
        trust_anchor_key: fx::TRUST_ANCHOR_KEY,
        authenticator_meta: fx::AUTHENTICATOR_META,
        nonce: fx::NONCE,
        rp_id: fx::RP_ID,
        now: fx::NOW,
        session_id: fx::SESSION_ID,
        genesis_issued_at_min: fx::GENESIS_ISSUED_AT_MIN,
        verifier_key: fx::VERIFIER_KEY,
        challenge_commitment: fx::CHALLENGE_COMMITMENT,
        comparison_age_max: fx::COMPARISON_AGE_MAX,
        similarity_min: fx::SIMILARITY_MIN,
        merkle_root: fx::MERKLE_ROOT,
        issuer_schema_id: fx::ISSUER_SCHEMA_ID,
        cred_pk: fx::CRED_PK,
        issuer_version: fx::ISSUER_VERSION,
        claim_index: fx::CLAIM_INDEX,
    }
}

fn run(publics: Publics, inputs: PrivateInputs) -> (Field, Field) {
    main(
        publics.trust_anchor_key,
        publics.authenticator_meta,
        publics.nonce,
        publics.rp_id,
        publics.now,
        publics.session_id,
        publics.genesis_issued_at_min,
        publics.verifier_key,
        publics.challenge_commitment,
        publics.comparison_age_max,
        publics.similarity_min,
        publics.merkle_root,
        publics.issuer_schema_id,
        publics.cred_pk,
        publics.issuer_version,
        publics.claim_index,
        inputs,
    )
}

/// Rewires the fixture to the 2-way flow: nil challenge commitment, nil
/// challenge score, and the Verifier signature over that digest.
fn two_way(publics: Publics, inputs: PrivateInputs) -> (Publics, PrivateInputs) {
    let mut publics = publics;
    let mut inputs = inputs;
    publics.challenge_commitment = 0;
    inputs.cwt.similarity_challenge = 0;
    inputs.cwt.sig_s = fx::CWT_SIG_S_TWO_WAY;
    inputs.cwt.sig_r = fx::CWT_SIG_R_TWO_WAY;
    (publics, inputs)
}

#[test]
fn test_accepts_valid_three_way_fixture() {
    let (sec_level, sec_meta) = run(fixture_publics(), fx::fixture_inputs());
    assert_eq(sec_level, fx::SEC_LEVEL);
    assert_eq(sec_meta, fx::SEC_META);
}

#[test]
fn test_accepts_two_way_flow() {
    let (publics, inputs) = two_way(fixture_publics(), fx::fixture_inputs());
    let _ = run(publics, inputs);
}

/// In the 2-way flow the challenge leg is skipped, so a threshold above the
/// (nil) challenge score must still pass while the live leg clears it.
#[test]
fn test_two_way_ignores_challenge_threshold() {
    let (mut publics, inputs) = two_way(fixture_publics(), fx::fixture_inputs());
    publics.similarity_min = 8500;
    let _ = run(publics, inputs);
}

// SECTION: verifier-supplied input validation (constraint 21)

#[test(should_fail_with = "nonce must not be zero")]
fn test_rejects_zero_nonce() {
    let mut publics = fixture_publics();
    publics.nonce = 0;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "now must not be zero")]
fn test_rejects_zero_now() {
    let mut publics = fixture_publics();
    publics.now = 0;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "similarity_min must not be zero")]
fn test_rejects_zero_similarity_min() {
    let mut publics = fixture_publics();
    publics.similarity_min = 0;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "comparison_age_max must not be zero")]
fn test_rejects_zero_comparison_age_max() {
    let mut publics = fixture_publics();
    publics.comparison_age_max = 0;
    let _ = run(publics, fx::fixture_inputs());
}

// SECTION: comparison age (constraint 15)

#[test(should_fail_with = "comparison must not be future-dated")]
fn test_rejects_future_dated_comparison() {
    let mut inputs = fx::fixture_inputs();
    inputs.cwt.iat = fx::FUTURE_IAT;
    inputs.cwt.sig_s = fx::CWT_SIG_S_FUTURE_IAT;
    inputs.cwt.sig_r = fx::CWT_SIG_R_FUTURE_IAT;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "comparison too old")]
fn test_rejects_stale_comparison() {
    // The fixture comparison is 60s old; a 30s bound must reject it.
    let mut publics = fixture_publics();
    publics.comparison_age_max = 30;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "comparison_age_max exceeds ceiling")]
fn test_rejects_excessive_comparison_age_max() {
    let mut publics = fixture_publics();
    publics.comparison_age_max = 86401;
    let _ = run(publics, fx::fixture_inputs());
}

// SECTION: similarity floor (constraint 19)

#[test(should_fail_with = "similarity_live below threshold")]
fn test_rejects_similarity_live_below_threshold() {
    let mut publics = fixture_publics();
    publics.similarity_min = 9001;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "similarity_challenge below threshold")]
fn test_rejects_similarity_challenge_below_threshold() {
    // Live (9000) clears the bound, challenge (8000) must not.
    let mut publics = fixture_publics();
    publics.similarity_min = 8500;
    let _ = run(publics, fx::fixture_inputs());
}

// SECTION: verifier token (constraints 14, 16, 18)

#[test(should_fail_with = "invalid verifier token signature")]
fn test_rejects_tampered_verifier_signature() {
    let mut inputs = fx::fixture_inputs();
    inputs.cwt.sig_s += 1;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "invalid verifier token signature")]
fn test_rejects_wrong_verifier_key() {
    let mut publics = fixture_publics();
    publics.verifier_key = fx::TRUST_ANCHOR_KEY;
    let _ = run(publics, fx::fixture_inputs());
}

/// Constraint 18: the public input is hashed into the signed digest, so a
/// value the Verifier did not sign cannot verify.
#[test(should_fail_with = "invalid verifier token signature")]
fn test_rejects_tampered_challenge_commitment() {
    let mut publics = fixture_publics();
    publics.challenge_commitment += 1;
    let _ = run(publics, fx::fixture_inputs());
}

/// A prover cannot inflate a score: it is covered by the Verifier signature.
#[test(should_fail_with = "invalid verifier token signature")]
fn test_rejects_tampered_similarity_score() {
    let mut inputs = fx::fixture_inputs();
    inputs.cwt.similarity_live = 9001;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_claim_index_out_of_range() {
    let mut publics = fixture_publics();
    publics.claim_index = 15;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "credential commitment mismatch")]
fn test_rejects_wrong_claim_index() {
    // Points at an unrelated (zero) claim, so the binding must fail.
    let mut publics = fixture_publics();
    publics.claim_index = 1;
    let _ = run(publics, fx::fixture_inputs());
}

// SECTION: registry and authorization (constraints 1-5, 10)

#[test(should_fail_with = "merkle proof verification failed")]
fn test_rejects_wrong_merkle_root() {
    let mut publics = fixture_publics();
    publics.merkle_root += 1;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "leaf_index must not be zero")]
fn test_rejects_zero_leaf_index() {
    let mut inputs = fx::fixture_inputs();
    inputs.registry.leaf_index = 0;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_pk_index_out_of_range() {
    let mut inputs = fx::fixture_inputs();
    inputs.registry.pk_index = 7;
    let _ = run(fixture_publics(), inputs);
}

/// Inactive slots hold the identity, which the EdDSA verifier refuses
/// (constraint 2).
#[test(should_fail_with = "Public key cannot be identity")]
fn test_rejects_unused_key_slot() {
    let mut inputs = fx::fixture_inputs();
    inputs.registry.pk_index = 1;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "invalid authenticator signature")]
fn test_rejects_tampered_authorization_signature() {
    let mut inputs = fx::fixture_inputs();
    inputs.registry.sig_s += 1;
    let _ = run(fixture_publics(), inputs);
}

/// The authorization message binds `rp_id`; a different audience must fail.
#[test(should_fail_with = "invalid authenticator signature")]
fn test_rejects_wrong_rp_id() {
    let mut publics = fixture_publics();
    publics.rp_id += 1;
    let _ = run(publics, fx::fixture_inputs());
}

/// The authorization message binds the RP `nonce`; replays under a fresh
/// nonce must fail.
#[test(should_fail_with = "invalid authenticator signature")]
fn test_rejects_wrong_nonce() {
    let mut publics = fixture_publics();
    publics.nonce += 1;
    let _ = run(publics, fx::fixture_inputs());
}

// SECTION: credential validity (constraints 6-9)

#[test(should_fail_with = "invalid credential signature")]
fn test_rejects_tampered_claims() {
    let mut inputs = fx::fixture_inputs();
    inputs.credential.claims[0] += 1;
    let _ = run(fixture_publics(), inputs);
}

/// The Issuer signature covers `issuer_version` through the packed
/// identifier (constraint 8).
#[test(should_fail_with = "invalid credential signature")]
fn test_rejects_wrong_issuer_version() {
    let mut publics = fixture_publics();
    publics.issuer_version = 0;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "invalid credential signature")]
fn test_rejects_wrong_issuer_schema_id() {
    let mut publics = fixture_publics();
    publics.issuer_schema_id += 1;
    let _ = run(publics, fx::fixture_inputs());
}

/// A credential signed over another registry leaf must not verify: `sub`
/// blinds the same `leaf_index` witness the Merkle proof runs on
/// (constraint 10). The Merkle check fails first for the tampered index.
#[test(should_fail_with = "merkle proof verification failed")]
fn test_rejects_wrong_leaf_index() {
    let mut inputs = fx::fixture_inputs();
    inputs.registry.leaf_index = 2;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "credential expired")]
fn test_rejects_expired_credential() {
    let mut inputs = fx::fixture_inputs();
    inputs.credential.expires_at = fx::EXPIRED_EXPIRES_AT;
    inputs.credential.sig_s = fx::CRED_SIG_S_EXPIRED;
    inputs.credential.sig_r = fx::CRED_SIG_R_EXPIRED;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "credential too recent")]
fn test_rejects_credential_before_genesis_minimum() {
    let mut publics = fixture_publics();
    publics.genesis_issued_at_min = 1600000001;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_cred_id_overflow() {
    let mut inputs = fx::fixture_inputs();
    inputs.credential.id = 0x10000000000000000;
    let _ = run(fixture_publics(), inputs);
}

// SECTION: attestation chain (constraints 11-13, 17)

#[test(should_fail_with = "invalid AAT signature")]
fn test_rejects_tampered_aat_signature() {
    let mut inputs = fx::fixture_inputs();
    inputs.aat_signature[0] += 1;
    let _ = run(fixture_publics(), inputs);
}

#[test(should_fail_with = "aat lifetime exceeds ceiling")]
fn test_rejects_aat_lifetime_beyond_ceiling() {
    let mut inputs = fx::fixture_inputs();
    inputs.aat_exp = fx::AAT_EXP_TOO_LONG;
    inputs.aat_signature = fx::AAT_SIGNATURE_TOO_LONG_EXP;
    let _ = run(fixture_publics(), inputs);
}

/// The TAKT must be signed by the RP-supplied `trust_anchor_key`
/// (constraint 11): the token is reassembled around the public input.
#[test(should_fail_with = "invalid signature")]
fn test_rejects_wrong_trust_anchor_key() {
    let mut publics = fixture_publics();
    publics.trust_anchor_key = fx::VERIFIER_KEY;
    let _ = run(publics, fx::fixture_inputs());
}

/// `authenticator_meta` is spliced into the signed AAT payload, so a public
/// input the Authenticator did not sign must fail (constraint 12).
#[test(should_fail_with = "invalid AAT signature")]
fn test_rejects_wrong_authenticator_meta() {
    let mut publics = fixture_publics();
    publics.authenticator_meta = 2;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "sec_flags bits 52-55 are reserved and must be 0")]
fn test_rejects_reserved_sec_flags_bits() {
    let mut inputs = fx::fixture_inputs();
    inputs.takt.sec_flags += 0x0010000000000000;
    let _ = run(fixture_publics(), inputs);
}

// SECTION: session commitment (constraint 20)

#[test]
fn test_accepts_nil_session_id() {
    let mut publics = fixture_publics();
    publics.session_id = 0;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "session_id must be nil or the session commitment")]
fn test_rejects_wrong_session_id() {
    let mut publics = fixture_publics();
    publics.session_id = 1;
    let _ = run(publics, fx::fixture_inputs());
}

#[test(should_fail_with = "session_id must be nil or the session commitment")]
fn test_rejects_wrong_session_blinder() {
    let mut inputs = fx::fixture_inputs();
    inputs.session_id_r += 1;
    let _ = run(fixture_publics(), inputs);
}
