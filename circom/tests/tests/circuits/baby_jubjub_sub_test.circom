pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

// wrapper because we can't have tags in main component
template BabyJubJubSubTest() {
    signal input lhs[2];
    signal input rhs[2];
    signal output out[2];

    BabyJubJubPoint() { twisted_edwards_in_subgroup } lhs_p;
    BabyJubJubPoint() { twisted_edwards_in_subgroup } rhs_p;
    lhs_p.x <== lhs[0];
    lhs_p.y <== lhs[1];
    rhs_p.x <== rhs[0];
    rhs_p.y <== rhs[1];
    BabyJubJubPoint() { twisted_edwards_in_subgroup } result <== BabyJubJubSub()(lhs_p, rhs_p);
    out[0] <== result.x;
    out[1] <== result.y;
}

component main = BabyJubJubSubTest();
