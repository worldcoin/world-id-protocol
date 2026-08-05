use super::constants::DS_SESSION_COMMITMENT;
use poseidon2::bn254::perm;

/// Recomputes the session id commitment, which is the billing tree leaf.
///
/// `H(DS_C || mt_index || r)`, identical to `SessionId::commitment` in
/// `world-id-primitives` and to `computed_id_commitment` in `oprf_nullifier.circom`.
///
/// Opening the leaf to `mt_index` is what stops one enrolled slot from being
/// re-used for a different World ID.
pub(crate) fn session_id_commitment(mt_index: Field, commitment_r: Field) -> Field {
    let state = perm::x5_3([DS_SESSION_COMMITMENT, mt_index, commitment_r]);
    state[1]
}

#[test]
fn test_commitment_deterministic() {
    assert_eq(session_id_commitment(1, 100), session_id_commitment(1, 100));
}

#[test]
fn test_commitment_binds_both_inputs() {
    let base = session_id_commitment(1, 100);
    assert(base != session_id_commitment(2, 100));
    assert(base != session_id_commitment(1, 200));
}
