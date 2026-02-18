pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

// wrapper because we can't have tags in main component
template BabyJubJubOnCurveTest() {
    signal input p[2];
    signal output out[2];

    BabyJubJubPoint() { twisted_edwards } result <== BabyJubJubCheck()(p[0], p[1]);
    out[0] <== result.x;
    out[1] <== result.y;
}

component main = BabyJubJubOnCurveTest();