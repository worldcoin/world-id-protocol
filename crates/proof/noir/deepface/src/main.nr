//! WIP-111 DeepFace Proof.
//!
//! Proves that a WIP-110 Verifier accepted a DeepFace comparison of the prover's Orb
//! credential image with a live capture (and optionally the RP's challenge), and that
//! a genuine Authenticator of the same World ID sent the compared request.
pub(crate) mod constants;
pub(crate) mod credential;
pub(crate) mod hashes_json;
pub(crate) mod merkle;
pub(crate) mod types;
pub(crate) mod verifier_token;
mod test_fixtures;
mod tests;

use authenticator_assertion::verify_aat;
use constants::{CLAIM_INDEX, DS_SESSION_COMMITMENT, DS_WIP_111, MAX_COMPARISON_AGE_SECS, NUM_KEYS};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;
use std::field::bn254::assert_lt;
use types::{PrivateInputs, PublicKey};

/// Range-checks a value to 64 bits so ordering comparisons run over integers.
fn checked_u64(value: Field) -> u64 {
    value.assert_max_bit_size::<64>();
    value as u64
}

/// Numbers in comments refer to WIP-111 section 2.4.
fn main(
    // WIP-110 Verifier and RP policy
    verifier_key: pub PublicKey,
    method: pub Field,
    assurance_level_min: pub Field,
    comparison_age_max: pub Field,
    challenge_hash: pub Field,
    now: pub Field,
    // WIP-106 Authenticator Assertion
    trust_anchor_key: pub PublicKey,
    aud: pub Field,
    nonce: pub Field,
    platform: pub u8,
    sec_level: pub u8,
    sec_meta: pub u8,
    // Credential validity
    merkle_root: pub Field,
    issuer_schema_id: pub Field,
    issuer_version: pub Field,
    cred_pk: pub PublicKey,
    genesis_issued_at_min: pub Field,
    session_id: pub Field,
    inputs: PrivateInputs,
) {
    assert(now != 0, "now must not be zero");
    assert(comparison_age_max != 0, "comparison_age_max must not be zero");

    let token = inputs.token;
    let registry = inputs.registry;
    // One `leaf_index` witness binds the authenticator key, the credential and the session.
    let leaf_index = registry.leaf_index;

    // 1. Verifier token.
    verifier_token::verify_verifier_token(token, verifier_key);

    // 2. Policy: method, assurance level and comparison age.
    assert(token.method == method, "unexpected method");
    token.assurance_level.assert_max_bit_size::<8>();
    assurance_level_min.assert_max_bit_size::<8>();
    assert(
        token.assurance_level as u8 >= assurance_level_min as u8,
        "assurance level below minimum",
    );
    let now_u64 = checked_u64(now);
    let iat = checked_u64(token.iat);
    let comparison_age_max_u64 = checked_u64(comparison_age_max);
    assert(iat <= now_u64, "comparison must not be future-dated");
    assert(now_u64 - iat <= comparison_age_max_u64, "comparison too old");
    assert(comparison_age_max_u64 <= MAX_COMPARISON_AGE_SECS, "comparison_age_max exceeds ceiling");

    // 3. Credential image: the thumbnail digest in `hashes.json` is the compared credential entry.
    assert(
        hashes_json::thumbnail_digest(inputs.hashes_json) == token.compared_entry_hash[0],
        "thumbnail does not match the compared credential entry",
    );

    // 4. Credential claim: `hashes.json` is what the Issuer committed to.
    assert(
        hashes_json::claims_hash_v1(inputs.hashes_json) == inputs.credential.claims[CLAIM_INDEX],
        "hashes.json does not match the credential claim",
    );

    // 5. Challenge: `0` on both sides in the 2-way flow.
    assert(token.compared_entry_hash[2] == challenge_hash, "challenge mismatch");

    // 6. Authenticator: the AAT vouches for the exact request the Verifier compared.
    let flags = verify_aat(
        inputs.aat,
        [trust_anchor_key.x, trust_anchor_key.y],
        now,
        aud,
        nonce,
        token.request_hash,
        inputs.aat_blind,
    );
    assert(flags.platform == platform, "platform mismatch");
    assert(flags.sec_level == sec_level, "sec_level mismatch");
    assert(flags.sec_meta == sec_meta, "sec_meta mismatch");

    // 7. Authorization by a registered key of this World ID.
    assert_lt(registry.pk_index, NUM_KEYS as Field);
    let pk = registry.user_pk[registry.pk_index as u32];
    let message = perm::x5_4([DS_WIP_111, token.request_hash, nonce, aud])[1];
    assert(
        verify_eddsa_poseidon2(pk.x, pk.y, registry.sig_s, registry.sig_r, message),
        "invalid authenticator signature",
    );

    // 8. Credential validity.
    let sub = credential::compute_sub(leaf_index, inputs.credential.sub_blinding_factor);
    credential::verify_credential_signature(
        inputs.credential,
        issuer_schema_id,
        issuer_version,
        sub,
        cred_pk,
    );
    assert(now_u64 < checked_u64(inputs.credential.expires_at), "credential expired");
    assert(
        checked_u64(genesis_issued_at_min) <= checked_u64(inputs.credential.genesis_issued_at),
        "credential too recent",
    );

    // 9. Registry inclusion of the key set.
    let key_set_commitment = merkle::key_set_commitment(registry.user_pk);
    assert(
        merkle::compute_merkle_root(key_set_commitment, leaf_index, registry.siblings)
            == merkle_root,
        "merkle proof verification failed",
    );

    // 10. Session: nil or the commitment over `leaf_index`.
    let session_commitment =
        perm::x5_3([DS_SESSION_COMMITMENT, leaf_index, inputs.session_id_r])[1];
    assert(
        session_id * (session_id - session_commitment) == 0,
        "session_id must be nil or the session commitment",
    );
}
