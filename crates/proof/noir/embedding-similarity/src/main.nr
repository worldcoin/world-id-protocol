//! WIP-111 Embedding Similarity Proof.
//!
//! Proves that an embedding committed in a user's Credential is similar to one
//! or two other embeddings, without revealing any of them: it verifies a
//! WIP-110 Verifier token, checks each commitment against the party that
//! vouches for it, checks the scores against the RP's threshold, and checks
//! the credential is valid. See `docs/WIPs/wip-111.md`.
pub(crate) mod constants;
pub(crate) mod credential;
pub(crate) mod merkle;
pub(crate) mod types;
pub(crate) mod verifier_token;
mod test_fixtures;
mod tests;

use authenticator_assertion::{
    aat::{AuthenticatorAssertionToken, verify_aat},
    takt::{TrustAnchorKeyToken, unpack_sec_flags},
};
use constants::{
    DS_SESSION_COMMITMENT, DS_WIP_111, MAX_AAT_LIFETIME_SECS, MAX_CLAIMS, MAX_COMPARISON_AGE_SECS,
    NUM_KEYS,
};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;
use std::field::bn254::assert_lt;
use types::{PrivateInputs, PublicKey};

/// Range-checks a value to 64 bits and returns it as a `u64` so ordering
/// comparisons run over the canonical integer representative, never over the
/// field (constraint preamble of WIP-111 section 3.5).
fn checked_u64(value: Field) -> u64 {
    value.assert_max_bit_size::<64>();
    value as u64
}

/// Constraint numbers in comments refer to WIP-111 section 3.5. Returns the
/// `sec_flags` sub-fields the RP's policy reads, `(sec_level, sec_meta)`, as
/// public outputs (constraint 12; the exposed set follows WIP-106
/// "Verification"; the packed `sec_flags` itself stays private).
fn main(
    // Authenticator Assertion (WIP-106)
    trust_anchor_key: pub PublicKey,
    authenticator_meta: pub Field,
    // RP inputs
    nonce: pub Field,
    rp_id: pub Field,
    now: pub Field,
    session_id: pub Field,
    genesis_issued_at_min: pub Field,
    // WIP-110 Verifier
    verifier_key: pub PublicKey,
    challenge_commitment: pub Field,
    comparison_age_max: pub Field,
    similarity_min: pub Field,
    // Credential validity
    merkle_root: pub Field,
    issuer_schema_id: pub Field,
    cred_pk: pub PublicKey,
    issuer_version: pub Field,
    claim_index: pub Field,
    inputs: PrivateInputs,
) -> pub (Field, Field) {
    // 21. Verifier-supplied input validation.
    assert(nonce != 0, "nonce must not be zero");
    assert(now != 0, "now must not be zero");
    assert(similarity_min != 0, "similarity_min must not be zero");
    assert(comparison_age_max != 0, "comparison_age_max must not be zero");

    let registry = inputs.registry;
    let cwt = inputs.cwt;
    // 10. One `leaf_index` witness: blinded into `sub` (6), proven in the
    // Merkle inclusion (4), and hashed into the session commitment (20).
    let leaf_index = registry.leaf_index;
    // 17. + 5. One `live_commitment` witness: the `cwt` claim, the AAT `cdh`
    // (spliced into the signed AAT below), and the authorized message.
    let live_commitment = cwt.live_commitment;

    // 14. Verifier token: digest over the claims (with `challenge_commitment`
    // bound to the public input, 18.) and EdDSA signature by `verifier_key`.
    verifier_token::verify_verifier_token(cwt, challenge_commitment, verifier_key);

    // 15. Comparison age: `iat <= now`, `now - iat <= comparison_age_max`
    // (underflow-safe only after the first check), RP bound backstopped.
    let now_u64 = checked_u64(now);
    let iat = checked_u64(cwt.iat);
    let comparison_age_max_u64 = checked_u64(comparison_age_max);
    assert(iat <= now_u64, "comparison must not be future-dated");
    assert(now_u64 - iat <= comparison_age_max_u64, "comparison too old");
    assert(comparison_age_max_u64 <= MAX_COMPARISON_AGE_SECS, "comparison_age_max exceeds ceiling");

    // 19. Similarity floor. `challenge_commitment == 0` is the 2-way flow: the
    // challenge leg is enforced exactly when the commitment is non-nil.
    let similarity_min_u64 = checked_u64(similarity_min);
    assert(
        checked_u64(cwt.similarity_live) >= similarity_min_u64,
        "similarity_live below threshold",
    );
    let is_absent = challenge_commitment == 0;
    let effective_min = if is_absent { 0 } else { similarity_min_u64 };
    assert(
        checked_u64(cwt.similarity_challenge) >= effective_min,
        "similarity_challenge below threshold",
    );

    // 1. + 2. Key selection: `pk_index < NUM_KEYS` over the full field, then
    // select. Inactive slots hold the identity (0, 1), which the signature
    // verification in 5. rejects.
    assert_lt(registry.pk_index, NUM_KEYS as Field);
    let pk = registry.user_pk[registry.pk_index as u32];

    // 3. + 4. Registry leaf and Merkle inclusion at the fixed depth of 30.
    let key_set_commitment = merkle::key_set_commitment(registry.user_pk);
    let computed_root =
        merkle::compute_merkle_root(key_set_commitment, leaf_index, registry.siblings);
    assert(computed_root == merkle_root, "merkle proof verification failed");

    // 5. Authenticator authorization over the live capture and the request.
    let message = perm::x5_4([DS_WIP_111, live_commitment, nonce, rp_id])[1];
    let is_valid = verify_eddsa_poseidon2(pk.x, pk.y, registry.sig_s, registry.sig_r, message);
    assert(is_valid, "invalid authenticator signature");

    // 6. - 9. Credential validity: subject, claims hash, Issuer signature and
    // validity window.
    let sub = credential::compute_sub(leaf_index, inputs.credential.sub_blinding_factor);
    credential::verify_credential_signature(
        inputs.credential,
        issuer_schema_id,
        issuer_version,
        sub,
        cred_pk,
    );
    let expires_at = checked_u64(inputs.credential.expires_at);
    let genesis_issued_at = checked_u64(inputs.credential.genesis_issued_at);
    let genesis_issued_at_min_u64 = checked_u64(genesis_issued_at_min);
    assert(now_u64 < expires_at, "credential expired");
    assert(genesis_issued_at_min_u64 <= genesis_issued_at, "credential too recent");

    // 11. + 13. + 17. Attestation chain. The token is reassembled from the
    // public inputs (`aud = rp_id`, `nonce`, `authenticator_meta`,
    // `trust_anchor_key`) and the `cdh`/`signal` claim from the `live_commitment`
    // witness, so the signatures enforce those equalities by construction.
    let takt = TrustAnchorKeyToken {
        exp: inputs.takt.exp,
        assertion_key_x: inputs.takt.assertion_key_x,
        assertion_key_y: inputs.takt.assertion_key_y,
        sec_flags: inputs.takt.sec_flags,
        sig_s: inputs.takt.sig_s,
        sig_r: inputs.takt.sig_r,
        trust_anchor_key_x: trust_anchor_key.x,
        trust_anchor_key_y: trust_anchor_key.y,
    };
    let aat = AuthenticatorAssertionToken {
        aud: rp_id,
        exp: inputs.aat_exp,
        nonce,
        signal: live_commitment,
        authenticator_meta,
        takt,
        signature: inputs.aat_signature,
    };
    verify_aat(aat, now);
    // `verify_aat` asserts `now < exp`, so the subtraction cannot underflow.
    let aat_exp = checked_u64(inputs.aat_exp);
    assert(aat_exp - now_u64 <= MAX_AAT_LIFETIME_SECS, "aat lifetime exceeds ceiling");

    // 16. Credential commitment binding: `claim_index < MAX_CLAIMS` over the
    // full field, selecting from the same `claims` witness the Issuer signed.
    assert_lt(claim_index, MAX_CLAIMS as Field);
    assert(
        cwt.credential_commitment == inputs.credential.claims[claim_index as u32],
        "credential commitment mismatch",
    );

    // 20. Session commitment: nil or the correct commitment over `leaf_index`.
    let session_commitment =
        perm::x5_3([DS_SESSION_COMMITMENT, leaf_index, inputs.session_id_r])[1];
    assert(
        session_id * (session_id - session_commitment) == 0,
        "session_id must be nil or the session commitment",
    );

    // 12. Assertion metadata exposure: range-checked unpack (reserved bits
    // zero happens inside `verify_aat` as well; this exposes the sub-fields).
    let (_platform, sec_level, _build_version, sec_meta) = unpack_sec_flags(inputs.takt.sec_flags);
    (sec_level, sec_meta)
}
