//! WIP-202 Proof of Embedding Similarity.
//!
//! Proves that a WIP-201 Flamingo Verifier matched a live capture and the RP's challenge
//! to the image committed in the prover's PoH Credential, and that the World ID account
//! holding the Credential authorized the result.
pub(crate) mod components;
pub(crate) mod constants;
pub(crate) mod flamingo_token;
pub(crate) mod hashes_json;
pub(crate) mod types;
mod test_fixtures;
mod tests;

use components::{authentication, credential::{self, CredentialPublic}, session, types::PublicKey};
use constants::{CLAIM_INDEX, DS_WIP_202_AUTH};
use flamingo_token::FlamingoTokenPublic;
use poseidon2::bn254::permutation;
use types::PrivateInputs;

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

    // 2. Challenge binding.
    assert(challenge_hash != 0, "challenge_hash must not be zero");
    assert(compared[2] == challenge_hash, "challenge mismatch");

    // 4. World ID Authentication over the authorization message. One `leaf_index`
    // witness binds the World ID, the Credential and the session.
    let message = permutation::t4([DS_WIP_202_AUTH, digest, verifier_key.x, verifier_key.y])[1];
    let leaf_index = authentication::verify(merkle_root, message, inputs.account);

    // 5. Session commitment.
    session::verify(session_id, leaf_index, inputs.session_id_r);

    // 6. Credential verification.
    let claims = credential::verify(
        CredentialPublic { cred_pk, issuer_schema_id, issuer_version, genesis_issued_at_min },
        now,
        leaf_index,
        inputs.credential,
    );

    // 3.1 `hashes.json` is what the Issuer committed to.
    assert(
        hashes_json::claims_hash_v1(inputs.hashes_json) == claims[CLAIM_INDEX],
        "hashes.json does not match the credential claim",
    );

    // 3.2-3.3 Its thumbnail digest is the compared Credential image.
    assert(
        hashes_json::thumbnail_digest(inputs.hashes_json) == compared[0],
        "thumbnail does not match the compared credential entry",
    );
}
