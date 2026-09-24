// Credential subject derivation (WIP-111 constraint 6) and the commitment that
// stands in for the delegated validation (constraints 7, 8 and 16).
use super::{
    constants::{DS_CREDENTIAL_SUB, DS_WIP_111_CRED, MAX_CLAIMS},
    types::{CredentialInputs, PublicKey},
};
use poseidon2::bn254::perm;
use std::field::bn254::assert_lt;

/// The blinded credential subject `sub = H_3(DS_CREDENTIAL_SUB; leaf_index, blinding_factor)`.
pub fn compute_sub(leaf_index: Field, sub_blinding_factor: Field) -> Field {
    perm::x5_3([DS_CREDENTIAL_SUB, leaf_index, sub_blinding_factor])[1]
}

/// The commitment the WIP-110 Verifier signs over the Credential it validated.
///
/// `issuer_version` and `claim_index` share one slot the way
/// `verify_credential_signature` packs `cred_id`; both are range-checked here,
/// so the packing stays injective and a prover cannot trade one against the
/// other.
///
/// `sub` MUST come from `compute_sub` over the same `leaf_index` witness proven
/// in the Merkle inclusion (constraint 10); the caller passes it in so the
/// binding is visible at the call site. Hashing this value into the token
/// digest is what makes the Verifier's claim about *this* Credential
/// unforgeable: the Issuer signature is never seen by the circuit.
pub fn compute_delegation_commitment(
    credential: CredentialInputs,
    issuer_schema_id: Field,
    issuer_version: Field,
    claim_index: Field,
    sub: Field,
    cred_pk: PublicKey,
) -> Field {
    issuer_version.assert_max_bit_size::<8>();
    assert_lt(claim_index, MAX_CLAIMS as Field);
    let selector_packed = issuer_version + claim_index * 0x100;

    perm::x5_8([
        DS_WIP_111_CRED,
        sub,
        issuer_schema_id,
        cred_pk.x,
        cred_pk.y,
        selector_packed,
        credential.genesis_issued_at,
        credential.expires_at,
    ])[1]
}
