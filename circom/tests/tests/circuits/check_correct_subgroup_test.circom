pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

template Tester() {
    signal input in[2];
    signal output out[2];

    BabyJubJubPoint() { twisted_edwards } p;
    p.x <== in[0];
    p.y <== in[1];

    BabyJubJubCheckInCorrectSubgroup()(p);
}

component main = Tester();
