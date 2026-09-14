//! WIP-111 Embedding Similarity Proof, variant WITHOUT in-circuit WIP-106
//! attestation verification.
//!
//! Identical to `embedding-similarity` except that the AAT/TAKT chain
//! (WIP-111 section 3.5 constraints 11-13 and 17) is not verified here: the
//! attestation is checked by the WIP-110 Verifier (TEE) before it signs its
//! token, so the RP's trust in the live capture's provenance rides on the
//! Verifier instead of the proof. The live capture stays bound to the World ID
//! holder through the authenticator authorization signature (constraint 5).
pub(crate) mod constants;
pub(crate) mod credential;
pub(crate) mod merkle;
pub(crate) mod types;
pub(crate) mod verifier_token;
mod test_fixtures;
mod tests;

use constants::{DS_SESSION_COMMITMENT, DS_WIP_111, MAX_CLAIMS, MAX_COMPARISON_AGE_SECS, NUM_KEYS};
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

/// Constraint numbers in comments refer to WIP-111 section 3.5.
fn main(
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
) {
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
    // 5. One `live_commitment` witness: the `cwt` claim and the authorized
    // message. Without the AAT there is no `cdh` to bind (17 is out of scope).
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
}
