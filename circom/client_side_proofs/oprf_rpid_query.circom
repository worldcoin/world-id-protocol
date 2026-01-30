pragma circom 2.2.2;

include "oprf_query.circom";

// Checks outside of the ZK proof: The output point q needs to be a valid BabyJubJub point in the correct subgroup.

template OprfRpIdQuery(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk correponding to pk is never used in a proof directly)
    signal input pk[7][2];
    signal input pk_index; // 0..6
    signal input s;
    signal input r[2];
    // Merkle proof
    signal input merkle_root; // Public
    signal input depth; // Public
    signal input mt_index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    // Nonce
    signal input nonce; // Public
    signal output q[2]; // Public

    component inner = OprfQueryInner(MAX_DEPTH);
    inner.pk <== pk;
    inner.pk_index <== pk_index;
    inner.s <== s;
    inner.r <== r;
    inner.merkle_root <== merkle_root;
    inner.depth <== depth;
    inner.mt_index <== mt_index;
    inner.siblings <== siblings;
    inner.beta <== beta;
    inner.query <== mt_index;
    q <== inner.q;

    // Dummy square to prevent tampering nonce.
    // Same as done in Semaphore
    signal nonce_squared <== nonce * nonce;
}

// component main {public [merkle_root, depth, nonce]} = OprfRpIdQuery(30);
