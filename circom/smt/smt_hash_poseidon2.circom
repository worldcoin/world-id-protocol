pragma circom 2.2.2;

// Hashes for the sparse Merkle tree, replacing iden3's classic-Poseidon
// SMTHash1/SMTHash2 with the Poseidon2 primitives used elsewhere in this repo.
//
// Source: https://github.com/iden3/circomlib/blob/master/circuits/smt/smthash_poseidon.circom

include "poseidon2/poseidon2.circom";

// Leaf hash. iden3 uses H(key, value, 1), where the trailing 1 separates leaves
// from internal nodes. Here the separation comes from the domain separator in
// the capacity element instead, so the extra input is dropped.
template SMTHash1() {
    signal input key;
    signal input value;
    signal output out;

    // b"World ID CRL leaf"
    var DS_CRL_LEAF = 29752704349928690492977588031568317079910;
    var h[3] = Poseidon2(3)([DS_CRL_LEAF, key, value]);
    out <== h[1];
}

// Internal node hash. Same compression mode as binary_merkle_root.circom, so
// both tree implementations agree on node hashing.
template SMTHash2() {
    signal input L;
    signal input R;
    signal output out;

    var h[2] = Poseidon2(2)([L, R]);
    out <== h[0] + L;
}
