use super::constants::{DS_CREDENTIAL_MESSAGE, DS_CREDENTIAL_SUB};
use super::types::{CredentialWitness, PublicKey};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

/// The credential subject commitment, `H(DS_CS_C || user_id || r)`.
///
/// `user_id` is the `mt_index`, which is what binds the credential to one World ID.
fn credential_sub(user_id: Field, blinding_factor: Field) -> Field {
    let state = perm::x5_3([DS_CREDENTIAL_SUB, user_id, blinding_factor]);
    state[1]
}

/// The message the issuer signs over.
///
/// Mirrors the `Poseidon2(8)` layout of `CheckCredentialSignature` in
/// `circom/client_side_proofs/oprf_nullifier.circom` field for field.
fn credential_message(
    issuer_schema_id: Field,
    sub: Field,
    genesis_issued_at: Field,
    expires_at: Field,
    claims_hash: Field,
    associated_data_hash: Field,
    cred_id: Field,
) -> Field {
    let state = perm::x5_8([
        DS_CREDENTIAL_MESSAGE,
        issuer_schema_id,
        sub,
        genesis_issued_at,
        expires_at,
        claims_hash,
        associated_data_hash,
        cred_id,
    ]);
    state[1]
}

/// Verifies a Proof of Human credential and that it belongs to `mt_index`.
///
/// `claims_hash` is passed in from the `pcp_hash` public input, so a valid proof ties
/// that PCP hash to this `mt_index` -- an enrolled World ID cannot be used to verify a
/// different human.
///
/// The two timestamp bounds are range checked before the `u64` comparisons so the casts
/// are sound. `oprf_nullifier.circom` leaves the two public timestamps to be checked
/// outside the proof; doing it in-circuit costs two 64-bit range checks and removes a
/// caller obligation.
pub(crate) fn verify_credential(
    credential: CredentialWitness,
    mt_index: Field,
    issuer_schema_id: Field,
    issuer_pk: PublicKey,
    claims_hash: Field,
    current_timestamp: Field,
    genesis_issued_at_min: Field,
) {
    let sub = credential_sub(mt_index, credential.sub_blinding_factor);

    let message = credential_message(
        issuer_schema_id,
        sub,
        credential.genesis_issued_at,
        credential.expires_at,
        claims_hash,
        credential.associated_data_hash,
        credential.cred_id,
    );

    let is_valid = verify_eddsa_poseidon2(
        issuer_pk.x,
        issuer_pk.y,
        credential.sig_s,
        credential.sig_r,
        message,
    );
    assert(is_valid, "Invalid credential signature");

    credential.genesis_issued_at.assert_max_bit_size::<64>();
    credential.expires_at.assert_max_bit_size::<64>();
    current_timestamp.assert_max_bit_size::<64>();
    genesis_issued_at_min.assert_max_bit_size::<64>();

    assert(current_timestamp as u64 < credential.expires_at as u64, "Credential expired");
    assert(
        genesis_issued_at_min as u64 <= credential.genesis_issued_at as u64,
        "Credential issued before the minimum genesis time",
    );
}

#[test]
fn test_credential_sub_binds_user_id() {
    assert(credential_sub(1, 7) != credential_sub(2, 7));
}

#[test]
fn test_credential_message_binds_claims_hash() {
    let a = credential_message(1, 2, 3, 4, 5, 6, 7);
    let b = credential_message(1, 2, 3, 4, 99, 6, 7);
    assert(a != b);
}
