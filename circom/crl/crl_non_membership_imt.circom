pragma circom 2.2.2;

include "merkle_tree/binary_merkle_root.circom";
include "poseidon2/poseidon2.circom";
include "circomlib/comparators.circom";
include "circomlib/bitify.circom";

// Non-membership proof against a credential revocation list held as an indexed
// Merkle tree (Aztec low-leaf style).
//
// Leaves form a linked list sorted ascending by `value`. Each leaf caches the
// next-larger value (`next_value`) so a single leaf proves both bounds around a
// gap. `next_value == 0` marks the tail of the list (+infinity).
//
// A key `k` is absent iff there is a leaf `L` in the tree with
// `L.value < k < L.next_value` (or `L.value < k` when `L` is the tail).
//
// `k = 0` is reserved: it collides with the sentinel head leaf `(0, 0, 0)`, so
// issuers must not issue `id = 0`.
//
// KEY_BITS bounds the comparator width and must cover the key: 64 for a raw
// `cred_id`, ~252 for a scoped hash `H(issuer_schema_id, cred_id)`.
template CrlNonMembershipIMT(MAX_CRL_DEPTH, KEY_BITS) {
    signal input crl_root;
    signal input crl_depth;
    signal input key;
    // The low leaf and its position in the tree.
    signal input low_value;
    signal input low_next_index;
    signal input low_next_value;
    signal input low_index;
    signal input crl_siblings[MAX_CRL_DEPTH];

    // Domain separator in the capacity element, b"World ID CRL leaf".
    var DS_CRL_LEAF = 29752704349928690492977588031568317079910;
    var leaf[4] = Poseidon2(4)([DS_CRL_LEAF, low_value, low_next_index, low_next_value]);

    signal computed_root <== BinaryMerkleRoot(MAX_CRL_DEPTH)(leaf[1], crl_depth, low_index, crl_siblings);
    computed_root === crl_root;

    // The bounds are committed in the tree, but still need range binding for the
    // comparators below to be sound.
    var key_in_range[KEY_BITS] = Num2Bits(KEY_BITS)(key);
    var low_in_range[KEY_BITS] = Num2Bits(KEY_BITS)(low_value);
    var next_in_range[KEY_BITS] = Num2Bits(KEY_BITS)(low_next_value);

    // Strict: `low_value == key` would mean the key is revoked.
    var gt_low = LessThan(KEY_BITS)([low_value, key]);
    gt_low === 1;

    // Upper bound, skipped when the low leaf is the tail of the list.
    signal is_tail <== IsZero()(low_next_value);
    signal lt_next <== LessThan(KEY_BITS)([key, low_next_value]);
    (1 - is_tail) * (1 - lt_next) === 0;
}
