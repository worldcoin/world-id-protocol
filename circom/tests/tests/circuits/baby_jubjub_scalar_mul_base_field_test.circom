pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

// wrapper because we can't have tags in main component
template BabyJubJubScalarMulBaseFieldTest() {
    signal input e;
    signal input x;
    signal input y;
    signal output out[2];

    BabyJubJubBaseField() in_e;
    BabyJubJubPoint() { twisted_edwards_in_subgroup } in_p;
    in_e.f <== e;
    in_p.x <== x;
    in_p.y <== y;
    BabyJubJubPoint() { twisted_edwards_in_subgroup } result <== BabyJubJubScalarMulBaseField()(in_e, in_p);
    out[0] <== result.x;
    out[1] <== result.y;
}

component main = BabyJubJubScalarMulBaseFieldTest();
