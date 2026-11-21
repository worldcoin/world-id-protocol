// XMSS (WOTS+ with w = 2) over Poseidon2, for authenticator credentials whose security rests only
// on hashes. w = 2 minimizes in-circuit hashing: the signature is a private witness, so its size
// does not matter.
use super::constants::{
    DS_XMSS_CHAIN, DS_XMSS_COMMIT, DS_XMSS_MSG, DS_XMSS_NODE, DS_XMSS_PK, DS_XMSS_TAG,
    DS_XMSS_TAG_KEY, WOTS_CHAINS, WOTS_CHECKSUM_CHAINS, WOTS_MSG_CHAINS, XMSS_HEIGHT,
};

/// An XMSS signature: the WOTS+ chain values, the one-time key index and its authentication path.
pub struct XmssSignature {
    pub chains: [Field; WOTS_CHAINS],
    pub index: Field,
    pub auth_path: [Field; XMSS_HEIGHT],
}

/// The XMSS key material that stays secret but is bound by the on-chain commitment.
pub struct XmssKey {
    pub pub_seed: Field,
    pub tag_key: Field,
}

/// Recomputes the XMSS root that `sig` over `message` belongs to.
pub fn root_from_signature(message: Field, sig: XmssSignature, pub_seed: Field) -> Field {
    sig.index.assert_max_bit_size::<XMSS_HEIGHT>();
    let digits = digits(h3(DS_XMSS_MSG, pub_seed, sig.index, message));

    // A chain signs digit 1 with its end value and digit 0 with the value one step before.
    let mut ends: [Field; WOTS_CHAINS] = [0; WOTS_CHAINS];
    for i in 0..WOTS_CHAINS {
        let stepped = chain_step(pub_seed, i, sig.chains[i]);
        ends[i] = if digits[i] { sig.chains[i] } else { stepped };
    }

    let index_bits: [bool; XMSS_HEIGHT] = sig.index.to_le_bits();
    let mut node = compress_public_key(ends, pub_seed);
    for level in 0..XMSS_HEIGHT {
        let sibling = sig.auth_path[level];
        let (left, right) = if index_bits[level] {
            (sibling, node)
        } else {
            (node, sibling)
        };
        node = h3(DS_XMSS_NODE, left, right, pub_seed + level as Field);
    }
    node
}

/// The on-chain commitment `H(DS_XMSS_COMMIT; root, pub_seed, H(DS_XMSS_TAG_KEY; tag_key))`.
pub fn commitment(root: Field, key: XmssKey) -> Field {
    h3(
        DS_XMSS_COMMIT,
        root,
        key.pub_seed,
        h3(DS_XMSS_TAG_KEY, key.tag_key, 0, 0),
    )
}

/// The public one-time-key tag the OPRF nodes deduplicate on; unlinkable without `tag_key`.
pub fn tag(tag_key: Field, index: Field) -> Field {
    h3(DS_XMSS_TAG, tag_key, index, 0)
}

pub fn chain_step(pub_seed: Field, chain: u32, value: Field) -> Field {
    h3(DS_XMSS_CHAIN, pub_seed, chain as Field, value)
}

/// The 254 digest bits followed by the 8-bit checksum (the count of zero bits).
fn digits(digest: Field) -> [bool; WOTS_CHAINS] {
    let message_bits: [bool; WOTS_MSG_CHAINS] = digest.to_le_bits();
    let mut out: [bool; WOTS_CHAINS] = [false; WOTS_CHAINS];
    let mut zeros: Field = 0;
    for i in 0..WOTS_MSG_CHAINS {
        out[i] = message_bits[i];
        zeros += 1 - message_bits[i] as Field;
    }
    let checksum_bits: [bool; WOTS_CHECKSUM_CHAINS] = zeros.to_le_bits();
    for i in 0..WOTS_CHECKSUM_CHAINS {
        out[WOTS_MSG_CHAINS + i] = checksum_bits[i];
    }
    out
}

/// Sponge over the chain ends: domain separator in the capacity, rate 3.
fn compress_public_key(ends: [Field; WOTS_CHAINS], pub_seed: Field) -> Field {
    let mut state = [DS_XMSS_PK, pub_seed, 0, 0];
    for block in 0..(WOTS_CHAINS + 2) / 3 {
        for lane in 0..3 {
            let i = block * 3 + lane;
            if i < WOTS_CHAINS {
                state[lane + 1] += ends[i];
            }
        }
        state = std::hash::poseidon2_permutation(state);
    }
    state[1]
}

/// `H(ds; a, b, c)` in the protocol layout (separator in slot 0, digest from slot 1), on the
/// native Poseidon2 black box.
pub fn h3(ds: Field, a: Field, b: Field, c: Field) -> Field {
    std::hash::poseidon2_permutation([ds, a, b, c])[1]
}

mod tests {
    use super::h3;
    use poseidon2::bn254::permutation;

    #[test]
    fn test_black_box_matches_library_permutation() {
        assert_eq(h3(1, 2, 3, 4), permutation::t4([1, 2, 3, 4])[1]);
    }
}
