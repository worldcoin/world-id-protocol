pragma circom 2.2.2;

include "merkle_tree/binary_merkle_root.circom";

// Non-membership proof against a credential revocation list held as a *full*
// fixed-depth sparse Merkle tree, keyed on the credential id.
//
// The key is the leaf position, so the tree has one leaf per possible key and
// its depth is the key width. A leaf is 0 when the credential is live and 1
// when it is revoked; empty subtrees are constant hashes per level.
//
// Non-membership is therefore just inclusion of an empty (0) leaf at
// `index = key` — no comparators, no low leaf, no auxiliary witness. Soundness
// comes from the position being the key: no sibling set reproduces the root
// with `leaf = 0` if the committed leaf is 1.
//
// KEY_BITS is both the key width and the tree depth, so this variant only works
// for a narrow key. A raw u64 `cred_id` gives 64; a scoped hash would need ~254
// levels, which is why the compressed variant exists.
template CrlNonMembershipSmtFull(KEY_BITS) {
    signal input crl_root;
    signal input key;
    signal input crl_siblings[KEY_BITS];

    signal computed_root <== BinaryMerkleRoot(KEY_BITS)(0, KEY_BITS, key, crl_siblings);
    computed_root === crl_root;
}

// Same check over a Merkle path without `BinaryMerkleRoot`'s dynamic-depth
// machinery (the per-level IsEqual + the trailing index-range constraints).
// The depth is fixed at compile time here, which is all this variant needs.
template CrlNonMembershipSmtFullFixedDepth(KEY_BITS) {
    signal input crl_root;
    signal input key;
    signal input crl_siblings[KEY_BITS];

    signal nodes[KEY_BITS + 1];
    nodes[0] <== 0;

    signal indices[KEY_BITS] <== Num2Bits(KEY_BITS)(key);

    for (var i = 0; i < KEY_BITS; i++) {
        var c[2][2] = [ [nodes[i], crl_siblings[i]], [crl_siblings[i], nodes[i]] ];
        var child_nodes[2] = MultiMux1(2)(c, indices[i]);
        // Compression mode, as in binary_merkle_root.circom.
        var poseidon_result[2] = Poseidon2(2)(child_nodes);
        nodes[i + 1] <== poseidon_result[0] + child_nodes[0];
    }

    nodes[KEY_BITS] === crl_root;
}
