pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

template BabyJubJubIsInFrTest() {
    signal input in;
    signal output out;

    component in_f = BabyJubJubIsInFr();
    in_f.in <== in;
    BabyJubJubScalarField() result <== in_f.out;
    out <== result.f;
}

component main = BabyJubJubIsInFrTest();
