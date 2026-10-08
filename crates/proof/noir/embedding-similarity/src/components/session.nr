// Session Commitment (WIP-202 constraint 5).
use super::constants::DS_SESSION_COMMITMENT;
use poseidon2::bn254::permutation;

/// `session_id` is `0` (no session) or the commitment of the World ID at `leaf_index`.
pub fn verify(session_id: Field, leaf_index: Field, session_id_r: Field) {
    let commitment = permutation::t3([DS_SESSION_COMMITMENT, leaf_index, session_id_r])[1];
    assert(
        session_id * (session_id - commitment) == 0,
        "session_id must be nil or the session commitment",
    );
}
