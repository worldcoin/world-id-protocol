//! Authorizes a fetch of the World ID's secret shares from the OPRF nodes with an XMSS signature,
//! so the authorization rests only on hashes. The nodes learn `leaf_index`.
use poseidon2::bn254::permutation;
use world_id_components::{
    constants::{DS_SHARE_FETCH, MERKLE_DEPTH, NUM_KEYS, NUM_XMSS_SLOTS},
    merkle::{compute_merkle_root, key_set_commitment},
    secret_share,
    types::PublicKey,
    xmss::{self, XmssKey, XmssSignature},
};

pub struct FetchInputs {
    pub user_pk: [PublicKey; NUM_KEYS],
    pub s_commitment: Field,
    /// The account's XMSS credential commitments; inactive slots hold `0`.
    pub xmss_commitments: [Field; NUM_XMSS_SLOTS],
    pub xmss_slot: Field,
    pub xmss_root: Field,
    pub key: XmssKey,
    pub sig: XmssSignature,
    pub siblings: [Field; MERKLE_DEPTH],
}

fn main(
    merkle_root: pub Field,
    leaf_index: pub Field,
    // Short replay window; the nodes also reject a repeated `tag`.
    epoch: pub Field,
    // Hash of the ML-KEM key the nodes encrypt the shares to.
    kem_pk_hash: pub Field,
    // One-time-key tag the nodes deduplicate on.
    tag: pub Field,
    inputs: FetchInputs,
) {
    let message = permutation::t4([DS_SHARE_FETCH, leaf_index, epoch, kem_pk_hash])[1];

    // 1. The XMSS signature verifies under a credential committed in the account.
    let root = xmss::root_from_signature(message, inputs.sig, inputs.key.pub_seed);
    assert(root == inputs.xmss_root, "signature does not match the XMSS root");
    inputs.xmss_slot.assert_max_bit_size::<3>();
    assert((inputs.xmss_slot as u8) < NUM_XMSS_SLOTS as u8, "xmss_slot out of range");
    assert(
        inputs.xmss_commitments[inputs.xmss_slot as u32] == xmss::commitment(root, inputs.key),
        "XMSS credential is not registered",
    );

    // 2. The tag belongs to the one-time key that signed.
    assert(xmss::tag(inputs.key.tag_key, inputs.sig.index) == tag, "tag mismatch");

    // 3. The credential set is part of the World ID's registry leaf.
    let leaf = secret_share::registry_leaf(
        key_set_commitment(inputs.user_pk),
        inputs.s_commitment,
        secret_share::xmss_set_root(inputs.xmss_commitments),
    );
    assert(
        compute_merkle_root(leaf, leaf_index, inputs.siblings) == merkle_root,
        "merkle proof verification failed",
    );
}
