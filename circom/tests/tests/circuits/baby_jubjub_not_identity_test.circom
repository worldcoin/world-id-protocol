pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

// wrapper because we can't have tags in main component
template BabyJubJubNotIdentityTest() {
    signal input p[2];

    BabyJubJubPoint() { twisted_edwards_in_subgroup } in_p;
    in_p.x <== p[0];
    in_p.y <== p[1];
    BabyJubJubCheckNotIdentity()(in_p);
}

component main = BabyJubJubNotIdentityTest();
