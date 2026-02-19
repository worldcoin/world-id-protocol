pragma circom 2.1.5;

// This file is copied from https://github.com/zk-kit/zk-kit.circom/blob/main/packages/binary-merkle-root/src/binary-merkle-root.circom and adapted to use Poseidon2 instead of Poseidon and use it in compression mode and not in sponge mode.

include "poseidon2/poseidon2.circom";
include "circomlib/mux1.circom";
include "circomlib/comparators.circom";

// This circuit is designed to calculate the root of a binary Merkle
// tree given a leaf, its depth, and the necessary sibling
// information (aka proof of membership) which includes the index (a decimal
// value whose binary representation defines the path indices)
// and the sibling nodes. If the number of siblings equals the depth,
// the index corresponds to the position of the leaf in the tree.
//
// A circuit is designed without the capability to iterate through
// a dynamic array. To address this, a parameter with the static maximum
// tree depth is defined (i.e. 'MAX_DEPTH'). And additionally, the circuit
// receives a dynamic depth as an input, which is utilized in calculating the
// true root of the Merkle tree. The actual depth of the Merkle tree
// may be equal to or less than the static maximum depth.
//
// NOTE: This circuit will successfully verify `out = 0` for `depth > MAX_DEPTH`.
// Make sure to enforce `depth <= MAX_DEPTH` outside the circuit.
template BinaryMerkleRoot(MAX_DEPTH) {
    signal input leaf, depth, index, siblings[MAX_DEPTH];

    signal output out;

    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leaf;

    signal roots[MAX_DEPTH];
    var root = 0;

    signal indices[MAX_DEPTH] <== Num2Bits(MAX_DEPTH)(index);
    signal is_depth[MAX_DEPTH + 1];
    signal should_be_zeros[MAX_DEPTH];

    for (var i = 0; i < MAX_DEPTH; i++) {
        var isDepth = IsEqual()([depth, i]);
        is_depth[i] <== isDepth;

        roots[i] <== isDepth * nodes[i];

        root += roots[i];

        var c[2][2] = [ [nodes[i], siblings[i]], [siblings[i], nodes[i]] ];
        var childNodes[2] = MultiMux1(2)(c, indices[i]);

        // Compression mode
        var poseidon_result[2] = Poseidon2(2)(childNodes);
        nodes[i + 1] <== poseidon_result[0] + childNodes[0];
    }

    var isDepth = IsEqual()([depth, MAX_DEPTH]);
    is_depth[MAX_DEPTH] <== isDepth;

    out <== root + isDepth * nodes[MAX_DEPTH];

    // For our use case we need to enforce that the index is in range. We do this by checking that for all bits greater than the depth, the index bit is zero.
    // We can reuse the isDepth signal from above to do this.
    // The following construction translates the one-hot vector isDepth to a vector where each element i is 1 starting with the 1 in isDepth and 0 before.
    // E.g., [0,0,1,0,0] is translated to [0,0,1,1,1].
    // Thus a constraint indices[i] * should_be_zeros[i] === 0 enforces that all bits in indices after the depth are zero.
    for (var i = 0; i < MAX_DEPTH; i++) {
        if (i == 0) {
            should_be_zeros[i] <== is_depth[i];
        } else {
            should_be_zeros[i] <== is_depth[i] + should_be_zeros[i-1];
        }
        should_be_zeros[i] * indices[i] === 0;
    }
}
