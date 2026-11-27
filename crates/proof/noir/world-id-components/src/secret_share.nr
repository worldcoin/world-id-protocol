// Secret-shared OPRF blinding secret `s`: its commitment, the registry leaf that carries it,
// and the OPRF query digest that depends on it.
use super::constants::{
    DS_QUERY_V2, DS_REGISTRY_LEAF, DS_SECRET_COMMITMENT, DS_XMSS_SET, NUM_XMSS_SLOTS,
};
use poseidon2::bn254::permutation;

/// `sCommit = H(DS_SECRET_COMMITMENT; s)`, write-once per World ID in the registry.
pub fn secret_commitment(s: Field) -> Field {
    permutation::t2([DS_SECRET_COMMITMENT, s])[1]
}

/// The registry leaf `H(DS_REGISTRY_LEAF; key_set_commitment, sCommit, xmss_set_root)`.
/// Accounts without XMSS credentials use `xmss_set_root = 0`.
pub fn registry_leaf(
    key_set_commitment: Field,
    s_commitment: Field,
    xmss_set_root: Field,
) -> Field {
    permutation::t4(
        [DS_REGISTRY_LEAF, key_set_commitment, s_commitment, xmss_set_root],
    )[1]
}

/// Commitment to the account's XMSS credential slots; inactive slots hold `0`.
pub fn xmss_set_root(commitments: [Field; NUM_XMSS_SLOTS]) -> Field {
    let mut state: [Field; 8] = [0; 8];
    state[0] = DS_XMSS_SET;
    for i in 0..NUM_XMSS_SLOTS {
        state[i + 1] = commitments[i];
    }
    permutation::t8(state)[1]
}

/// The OPRF query digest `q' = H(DS_QUERY_V2; leaf_index, rp_id, action, s)`. Every OPRF output
/// derived from it depends on `s`, so recovering the OPRF key alone does not let anyone
/// recompute it.
pub fn query(leaf_index: Field, rp_id: Field, action: Field, s: Field) -> Field {
    permutation::t8([DS_QUERY_V2, leaf_index, rp_id, action, s, 0, 0, 0])[1]
}

mod tests {
    use super::{query, registry_leaf, secret_commitment};

    #[test]
    fn test_query_binds_secret() {
        assert(query(1, 2, 3, 4) != query(1, 2, 3, 5));
    }

    #[test]
    fn test_registry_leaf_binds_every_input() {
        let leaf = registry_leaf(1, secret_commitment(2), 3);
        assert(leaf != registry_leaf(9, secret_commitment(2), 3));
        assert(leaf != registry_leaf(1, secret_commitment(9), 3));
        assert(leaf != registry_leaf(1, secret_commitment(2), 9));
    }
}
