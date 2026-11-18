pragma circom 2.2.2;

// One level of the SMT verifier: emits the node root implied by the level state.
//
// Vendored from
// https://github.com/iden3/circomlib/blob/master/circuits/smt/smtverifierlevel.circom
// with SMTHash2 pointing at the Poseidon2 port.

include "circomlib/switcher.circom";
include "smt/smt_hash_poseidon2.circom";

template SMTVerifierLevel() {
    signal input st_top;
    signal input st_i0;
    signal input st_iold;
    signal input st_inew;
    signal input st_na;

    signal output root;
    signal input sibling;
    signal input old1leaf;
    signal input new1leaf;
    signal input lrbit;
    signal input child;

    signal aux[2];

    component proofHash = SMTHash2();
    component switcher = Switcher();

    switcher.L <== child;
    switcher.R <== sibling;

    switcher.sel <== lrbit;
    proofHash.L <== switcher.outL;
    proofHash.R <== switcher.outR;

    aux[0] <== proofHash.out * st_top;
    aux[1] <== old1leaf*st_iold;

    root <== aux[0] + aux[1] + new1leaf*st_inew;
}
