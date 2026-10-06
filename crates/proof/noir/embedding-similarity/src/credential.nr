// PoH Credential signature (WIP-202 constraint 8).
use super::{
    constants::{DS_CREDENTIAL_SUB, DS_CREDENTIAL_V1, MAX_CLAIMS},
    types::{CredentialInputs, PublicKey},
};
use poseidon2::bn254::permutation;

/// The blinded credential subject `sub = H_3(DS_CREDENTIAL_SUB; leaf_index, blinding_factor)`.
pub fn compute_sub(leaf_index: Field, sub_blinding_factor: Field) -> Field {
    permutation::t3([DS_CREDENTIAL_SUB, leaf_index, sub_blinding_factor])[1]
}

/// The claims hash: the Poseidon2 t=16 permutation over `[claims[0], ..., claims[14], 0]`,
/// state index 15 the fixed zero capacity element, digest at output state element 1.
///
/// This construction carries no domain separator and matches neither H_t nor
/// H_var of WIP-100; it is the Credential V1 claims hash.
// FIXME: UPDATE TO CREDENTIAL V2, the way `claims_hash` is computed will change.
pub fn claims_hash(claims: [Field; MAX_CLAIMS]) -> Field {
    let mut state: [Field; 16] = [0; 16];
    for i in 0..MAX_CLAIMS {
        state[i] = claims[i];
    }
    permutation::t16(state)[1]
}

/// Verifies the Issuer signature over the Credential.
///
/// `sub` MUST come from `compute_sub` over the same `leaf_index` witness proven
/// in the Merkle inclusion; the caller passes it in so the
/// binding is visible at the call site.
pub fn verify_credential_signature(
    credential: CredentialInputs,
    issuer_schema_id: Field,
    issuer_version: Field,
    sub: Field,
    cred_pk: PublicKey,
) {
    // The Issuer signature covers `issuer_version` through the packed
    // identifier; signing `id` alone would reject every credential whose
    // `issuer_version` is not 0.
    credential.id.assert_max_bit_size::<64>();
    issuer_version.assert_max_bit_size::<8>();
    let id_packed = credential.id + issuer_version * 0x10000000000000000;

    let message = permutation::t8([
        DS_CREDENTIAL_V1,
        issuer_schema_id,
        sub,
        credential.genesis_issued_at,
        credential.expires_at,
        claims_hash(credential.claims),
        credential.associated_data_hash,
        id_packed,
    ])[1];

    assert(credential.sig.verify(cred_pk, message), "invalid credential signature");
}
