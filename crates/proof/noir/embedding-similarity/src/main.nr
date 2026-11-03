//! WIP-202 Proof of Embedding Similarity.
//!
//! Proves that a WIP-201 Flamingo Verifier matched a live capture and the RP's challenge
//! to the image committed in the prover's PoH Credential, and that the World ID account
//! holding the Credential authorized the result.
pub(crate) mod constants;
pub(crate) mod hashes_json;
pub(crate) mod types;
mod test_fixtures;
mod tests;

use constants::{CLAIM_INDEX, COMPARE_SOURCES, DS_OPRF_PROOF, DS_QUERY, DS_WIP_202_AUTH};
use flamingo_token::{FlamingoTokenClaims, FlamingoTokenPublic};
use poseidon2::bn254::permutation;
use types::PrivateInputs;
use world_id_components::{
    authentication,
    credential::{self, CredentialPublic},
    session,
    types::PublicKey,
};

/// Numbers refer to WIP-202 §4.6 Circuit Constraints; they hold jointly, so order follows data flow.
fn main(
    // Proof time
    now: pub u32,
    // RP request
    rp_id: pub Field,
    nonce: pub Field,
    challenge_hash: pub Field,
    signal_hash: pub Field,
    session_id: pub Field,
    // WIP-201 Flamingo Token
    flamingo_verifier_key: pub PublicKey,
    engine_config_hash: pub Field,
    // Its AAT values
    has_aat: pub bool,
    trust_anchor_key_hash: pub Field,
    platform: pub u8,
    sec_level: pub u8,
    sec_meta: pub u8,
    authenticator_meta: pub u8,
    // World ID and Credential
    merkle_root: pub Field,
    issuer_schema_id: pub Field,
    issuer_version: pub Field,
    cred_pk: pub PublicKey,
    genesis_issued_at_min: pub Field,
    expires_at_min: pub Field,
    inputs: PrivateInputs,
) {
    // 2. Challenge present: `0` marks an unused position.
    assert(challenge_hash != 0, "challenge_hash must not be zero");

    // 3.2 The thumbnail digest is the Credential image the token must have compared.
    let credential_digest = hashes_json::thumbnail_digest(inputs.hashes_json);

    // 1. Flamingo Token verification; fixing the entries binds the Credential image and challenge.
    let public = FlamingoTokenPublic {
        verifier_key: flamingo_verifier_key,
        now: now as Field,
        aud: rp_id,
        nonce,
        has_aat: has_aat as Field,
        trust_anchor_key_hash,
        platform: platform as Field,
        sec_level: sec_level as Field,
        sec_meta: sec_meta as Field,
        authenticator_meta: authenticator_meta as Field,
        // WIP-202 checks no Authenticator build version for now.
        min_build_version: 0,
        engine_config_hash,
    };
    let billing_nullifier = inputs.token.billing_nullifier;
    let token_claims = FlamingoTokenClaims {
        compared_entry_hashes: [
            credential_digest,
            inputs.token.live_capture_hash,
            challenge_hash,
            0,
        ],
        compare_sources: COMPARE_SOURCES as Field,
        billing_nullifier,
    };
    let digest = flamingo_token::verify(public, token_claims, inputs.token.sig);

    // 4. World ID Authentication over the authorization message, which also binds the
    // RP's signal. One `leaf_index` witness binds the World ID, the Credential and the session.
    let message = permutation::t8([
        DS_WIP_202_AUTH,
        digest,
        flamingo_verifier_key.x,
        flamingo_verifier_key.y,
        signal_hash,
        0,
        0,
        0,
    ])[1];
    let leaf_index = authentication::verify(merkle_root, message, inputs.account);

    // 5. Session commitment.
    session::verify(session_id, leaf_index, inputs.session_id_r);

    // 6. Credential verification.
    let claims = credential::verify(
        CredentialPublic { cred_pk, issuer_schema_id, issuer_version, genesis_issued_at_min },
        now as Field,
        leaf_index,
        inputs.credential,
    );
    // The RP's minimum expiration, as in Uniqueness and Session Proofs; `verify` range-checks
    // `expires_at`.
    expires_at_min.assert_max_bit_size::<64>();
    assert(
        (expires_at_min as u64) < (inputs.credential.expires_at as u64),
        "credential expires too early",
    );

    // 7. Billing nullifier ownership: `0` means the RP is not billed, anything else must be this
    // World ID's WIP-107 nullifier for `rp_id`, recomputed as in the Uniqueness Proof.
    // The OPRF output is not checked to be on the curve: registration verified it, and a wrong
    // output only yields a nullifier the Verifier never signs (WIP-202 Rationale 8).
    let billing_query = permutation::t4([DS_QUERY, leaf_index, rp_id, inputs.billing_action])[1];
    let own_nullifier = permutation::t4([
        DS_OPRF_PROOF,
        billing_query,
        inputs.billing_oprf_output[0],
        inputs.billing_oprf_output[1],
    ])[1];
    assert(
        billing_nullifier * (billing_nullifier - own_nullifier) == 0,
        "billing nullifier is not this World ID's",
    );

    // 3.1 `hashes.json` is what the Issuer committed to.
    assert(
        hashes_json::claims_hash_v1(inputs.hashes_json) == claims[CLAIM_INDEX],
        "hashes.json does not match the credential claim",
    );
}
