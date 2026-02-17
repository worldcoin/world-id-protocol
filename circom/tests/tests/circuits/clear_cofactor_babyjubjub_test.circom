pragma circom 2.2.2;

include "encode_to_curve_babyjj/encode_to_curve_babyjj.circom";

template ClearCoFactorBabyJubJubMain() {
    input signal in[2];
    output signal out[2];

    BabyJubJubPoint() { twisted_edwards } inp;
    inp.x <== in[0];
    inp.y <== in[1];

    component test = ClearCoFactorBabyJubJub();
    test.in <== inp;
    out[0] <== test.out.x;
    out[1] <== test.out.y;
}

component main = ClearCoFactorBabyJubJubMain();
