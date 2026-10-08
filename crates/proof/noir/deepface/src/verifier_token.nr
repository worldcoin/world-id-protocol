// WIP-110 Verifier token verification.
use super::{constants::DS_EVT_V1, types::{PublicKey, VerifierTokenInputs}};
use poseidon2::bn254::permutation;

/// Verifies the Verifier's EdDSA signature over the WIP-110 digest: output element 1
/// of the Poseidon2 t=16 permutation over the domain separator and the claims.
pub fn verify_verifier_token(token: VerifierTokenInputs, verifier_key: PublicKey) {
    let h = token.compared_entry_hash;
    let digest = permutation::t16([
        DS_EVT_V1,
        token.iat,
        token.method,
        token.assurance_level,
        token.request_hash,
        h[0],
        h[1],
        h[2],
        h[3],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ])[1];

    assert(
        verifier_key.verify(token.sig_s, token.sig_r, digest),
        "invalid verifier token signature",
    );
}
