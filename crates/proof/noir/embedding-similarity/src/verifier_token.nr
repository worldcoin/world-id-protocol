// WIP-110 Verifier token (`cwt`) verification (WIP-111 constraint 14).
use super::{constants::DS_EVT_V1, types::{PublicKey, VerifierTokenInputs}};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

/// Verifies the Verifier's EdDSA signature over the token digest defined in
/// WIP-110 section 3.5.2. The claims are field elements; no CBOR is parsed or
/// reconstructed.
///
/// `challenge_commitment` is the public input: hashing it into the signed
/// digest is what binds the token's claim to it (constraint 18) -- a nil public
/// input therefore requires the signed claim to be 0, the 2-way flow.
pub fn verify_verifier_token(
    token: VerifierTokenInputs,
    challenge_commitment: Field,
    verifier_key: PublicKey,
) {
    let digest = perm::x5_8([
        DS_EVT_V1,
        token.iat,
        token.credential_commitment,
        token.live_commitment,
        challenge_commitment,
        token.similarity_live,
        token.similarity_challenge,
        0,
    ])[1];

    let is_valid = verify_eddsa_poseidon2(
        verifier_key.x,
        verifier_key.y,
        token.sig_s,
        token.sig_r,
        digest,
    );
    assert(is_valid, "invalid verifier token signature");
}
