//! WIP-111 Embedding Similarity Proof, variant that keeps only the
//! `WorldIDRegistry` inclusion in-circuit.
//!
//! On top of `embedding-similarity-no-attestation` -- which already delegates
//! the WIP-106 AAT/TAKT chain to the WIP-110 Verifier (TEE) -- this variant
//! also delegates Credential validation: the Verifier checks the Issuer
//! signature, the claims hash and the claim selection (constraints 7, 8 and
//! 16), and commits to what it validated in a `delegation_commitment` claim
//! carried in the spare slot of the WIP-110 token digest:
//!
//!   delegation_commitment = H_8(DS_WIP_111_CRED;
//!       sub, issuer_schema_id, cred_pk.x, cred_pk.y,
//!       issuer_version + claim_index * 2^8,
//!       cred_genesis_issued_at, cred_expires_at)
//!
//! The circuit recomputes that commitment from its own `sub` -- derived from
//! the `leaf_index` it proved inclusion for -- and from the RP's public
//! credential policy, so verifying the token signature enforces every one of
//! those equalities by construction.
//!
//! What cannot move, and stays here: the Merkle inclusion, and the
//! authenticator authorization signature (constraint 5). Checking that
//! signature means knowing which registered key signed, which means knowing
//! `leaf_index` -- the value the Verifier must not learn. It is also the only
//! constraint binding the live capture to the proven leaf.
//!
//! Privacy cost: verifying the Issuer signature requires seeing `sub`, a
//! stable per-credential pseudonym, so the Verifier can link a user's sessions
//! exactly rather than biometrically. It does not learn `leaf_index`, so the
//! pseudonym stays credential-scoped and rotates with the Credential.
pub(crate) mod constants;
pub(crate) mod credential;
pub(crate) mod merkle;
pub(crate) mod types;
pub(crate) mod verifier_token;
mod test_fixtures;
mod tests;

use constants::{DS_SESSION_COMMITMENT, DS_WIP_111, MAX_COMPARISON_AGE_SECS, NUM_KEYS};
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
    // Credential policy
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

    // 1. + 2. Key selection: `pk_index < NUM_KEYS` over the full field, then
    // select. Inactive slots hold the identity (0, 1), which the signature
    // verification in 5. rejects.
    assert_lt(registry.pk_index, NUM_KEYS as Field);
    let pk = registry.user_pk[registry.pk_index as u32];

    // 3. + 4. Registry leaf and Merkle inclusion at the fixed depth of 30.
    // The registry block runs before the delegated-credential block so a bad
    // `leaf_index` reports as a Merkle failure rather than as the token
    // signature mismatch it would also cause: `sub` is derived from the same
    // witness below.
    let key_set_commitment = merkle::key_set_commitment(registry.user_pk);
    let computed_root =
        merkle::compute_merkle_root(key_set_commitment, leaf_index, registry.siblings);
    assert(computed_root == merkle_root, "merkle proof verification failed");

    // 5. Authenticator authorization over the live capture and the request.
    let message = perm::x5_4([DS_WIP_111, live_commitment, nonce, rp_id])[1];
    let is_valid = verify_eddsa_poseidon2(pk.x, pk.y, registry.sig_s, registry.sig_r, message);
    assert(is_valid, "invalid authenticator signature");

    // 6. The blinded subject, over the `leaf_index` just proven: the only
    // value tying the delegated Credential back to the registry leaf.
    let sub = credential::compute_sub(leaf_index, inputs.credential.sub_blinding_factor);

    // 7. + 8. + 16. (delegated) The commitment the Verifier signed over the
    // Credential it validated, recomputed from `sub` and the RP's public
    // policy, so hashing it into the token digest (14.) enforces the Issuer
    // key, schema, version and claim slot by construction.
    let delegation_commitment = credential::compute_delegation_commitment(
        inputs.credential,
        issuer_schema_id,
        issuer_version,
        claim_index,
        sub,
        cred_pk,
    );

    // 14. Verifier token: digest over the claims (with `challenge_commitment`
    // bound to the public input, 18., and `delegation_commitment` bound to the
    // recomputed value) and EdDSA signature by `verifier_key`.
    verifier_token::verify_verifier_token(
        cwt,
        challenge_commitment,
        delegation_commitment,
        verifier_key,
    );

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

    // 9. Credential validity window. Only the signature moved to the Verifier:
    // the window still runs here, against the RP's `now` and
    // `genesis_issued_at_min`, on the same timestamps the delegation
    // commitment binds. Keeping it in-circuit avoids trusting the Verifier's
    // clock for RP freshness policy.
    let expires_at = checked_u64(inputs.credential.expires_at);
    let genesis_issued_at = checked_u64(inputs.credential.genesis_issued_at);
    let genesis_issued_at_min_u64 = checked_u64(genesis_issued_at_min);
    assert(now_u64 < expires_at, "credential expired");
    assert(genesis_issued_at_min_u64 <= genesis_issued_at, "credential too recent");

    // 20. Session commitment: nil or the correct commitment over `leaf_index`.
    let session_commitment =
        perm::x5_3([DS_SESSION_COMMITMENT, leaf_index, inputs.session_id_r])[1];
    assert(
        session_id * (session_id - session_commitment) == 0,
        "session_id must be nil or the session commitment",
    );
}
