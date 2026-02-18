pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

// wrapper because we can't have tags in main component
template BabyJubJubScalarMulGeneratorTest() {
    signal input e;
    signal output out[2];

    BabyJubJubScalarField() in_e;
    in_e.f <== e;
    BabyJubJubPoint() { twisted_edwards_in_subgroup } result <== BabyJubJubScalarGenerator()(in_e);
    out[0] <== result.x;
    out[1] <== result.y;
}

component main = BabyJubJubScalarMulGeneratorTest();
