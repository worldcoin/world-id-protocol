// Credential Verification (WIP-202 constraint 6).
use super::{
    constants::{DS_CREDENTIAL_SUB, DS_CREDENTIAL_V1, MAX_CLAIMS},
    types::{CredentialInputs, PublicKey},
};
use poseidon2::bn254::permutation;

/// The public values a Credential is verified against.
pub struct CredentialPublic {
    pub cred_pk: PublicKey,
    pub issuer_schema_id: Field,
    pub issuer_version: Field,
    pub genesis_issued_at_min: Field,
}

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

/// Range-checks a value to 64 bits so ordering comparisons run over integers.
fn checked_u64(value: Field) -> u64 {
    value.assert_max_bit_size::<64>();
    value as u64
}

/// Proves that the Issuer issued the Credential to the World ID at `leaf_index` and that it
/// is valid at `now`, and returns its claims.
pub fn verify(
    public: CredentialPublic,
    now: u32,
    leaf_index: Field,
    credential: CredentialInputs,
) -> [Field; MAX_CLAIMS] {
    // The Issuer signature covers `issuer_version` through the packed identifier.
    credential.id.assert_max_bit_size::<64>();
    public.issuer_version.assert_max_bit_size::<8>();
    let id_packed = credential.id + public.issuer_version * 0x10000000000000000;

    let message = permutation::t8([
        DS_CREDENTIAL_V1,
        public.issuer_schema_id,
        compute_sub(leaf_index, credential.sub_blinding_factor),
        credential.genesis_issued_at,
        credential.expires_at,
        claims_hash(credential.claims),
        credential.associated_data_hash,
        id_packed,
    ])[1];
    assert(credential.sig.verify(public.cred_pk, message), "invalid credential signature");

    assert((now as u64) < checked_u64(credential.expires_at), "credential expired");
    assert(
        checked_u64(public.genesis_issued_at_min) <= checked_u64(credential.genesis_issued_at),
        "credential too recent",
    );
    credential.claims
}
