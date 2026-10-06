//! WIP-202 Proof of Embedding Similarity.
//!
//! Proves that a WIP-201 Flamingo Verifier matched a live capture and the RP's challenge
//! to the image committed in the prover's PoH Credential, and that the World ID account
//! holding the Credential authorized the result.
pub(crate) mod constants;
pub(crate) mod credential;
pub(crate) mod flamingo_token;
pub(crate) mod hashes_json;
pub(crate) mod merkle;
pub(crate) mod types;
mod test_fixtures;
mod tests;

use constants::{CLAIM_INDEX, DS_SESSION_COMMITMENT, DS_WIP_202_AUTH, NUM_KEYS};
use flamingo_token::FlamingoTokenPublic;
use poseidon2::bn254::permutation;
use types::{PrivateInputs, PublicKey};

/// Range-checks a value to 64 bits so ordering comparisons run over integers.
fn checked_u64(value: Field) -> u64 {
    value.assert_max_bit_size::<64>();
    value as u64
}

/// Numbers in comments refer to WIP-202 section 4.6.
fn main(
    // WIP-201 Flamingo Token
    verifier_key: pub PublicKey,
    now: pub u32,
    aud: pub Field,
    nonce: pub Field,
    has_aat: pub bool,
    authenticator_provider_key_hash: pub Field,
    platform: pub u8,
    sec_level: pub u8,
    sec_meta: pub u8,
    user_presence: pub u8,
    min_build_version: pub u32,
    engine_config_hash: pub Field,
    // WIP-202
    challenge_hash: pub Field,
    merkle_root: pub Field,
    issuer_schema_id: pub Field,
    issuer_version: pub Field,
    cred_pk: pub PublicKey,
    genesis_issued_at_min: pub Field,
    session_id: pub Field,
    inputs: PrivateInputs,
) {
    let token = inputs.token;
    let account = inputs.account;
    let credential = inputs.credential;
    // One `leaf_index` witness binds the account, the Credential and the session.
    let leaf_index = account.leaf_index;

    // 1. Flamingo Token verification.
    let public = FlamingoTokenPublic {
        verifier_key,
        now,
        aud,
        nonce,
        has_aat,
        authenticator_provider_key_hash,
        platform,
        sec_level,
        sec_meta,
        user_presence,
        min_build_version,
        engine_config_hash,
    };
    let digest = flamingo_token::verify(public, token);
    let compared = token.compared_entry_hash;

    // 2. Challenge.
    assert(challenge_hash != 0, "challenge_hash must not be zero");
    assert(compared[2] == challenge_hash, "challenge mismatch");
    assert(compared[3] == 0, "unexpected fourth compared entry");

    // 3. Credential image: the thumbnail digest in `hashes.json` is the compared entry.
    assert(
        hashes_json::thumbnail_digest(inputs.hashes_json) == compared[0],
        "thumbnail does not match the compared credential entry",
    );

    // 4. Key selection.
    account.pk_index.assert_max_bit_size::<3>();
    assert((account.pk_index as u8) < NUM_KEYS as u8, "pk_index out of range");
    let pk = account.user_pk[account.pk_index as u32];

    // 5. Registry inclusion of the key set.
    let leaf = merkle::key_set_commitment(account.user_pk);
    assert(
        merkle::compute_merkle_root(leaf, leaf_index, account.siblings) == merkle_root,
        "merkle proof verification failed",
    );

    // 6. Authorization of the result by a registered key.
    let message = permutation::t4([DS_WIP_202_AUTH, digest, verifier_key.x, verifier_key.y])[1];
    assert(account.auth.verify(pk, message), "invalid authorization signature");

    // 7. Claims binding: `hashes.json` is what the Issuer committed to.
    assert(
        hashes_json::claims_hash_v1(inputs.hashes_json) == credential.claims[CLAIM_INDEX],
        "hashes.json does not match the credential claim",
    );

    // 8. Credential signature.
    let sub = credential::compute_sub(leaf_index, credential.sub_blinding_factor);
    credential::verify_credential_signature(
        credential,
        issuer_schema_id,
        issuer_version,
        sub,
        cred_pk,
    );

    // 9. Credential validity.
    assert((now as u64) < checked_u64(credential.expires_at), "credential expired");
    assert(
        checked_u64(genesis_issued_at_min) <= checked_u64(credential.genesis_issued_at),
        "credential too recent",
    );

    // 10. Session: nil or the commitment over `leaf_index`.
    let session_commitment =
        permutation::t3([DS_SESSION_COMMITMENT, leaf_index, inputs.session_id_r])[1];
    assert(
        session_id * (session_id - session_commitment) == 0,
        "session_id must be nil or the session commitment",
    );
}
