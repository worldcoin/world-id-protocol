pragma circom 2.2.2;

include "encode_to_curve_babyjj/encode_to_curve_babyjj.circom";

template EncodeToCurveBabyJubJubMain() {
    input signal in;
    output signal out[2];

    component encode_to_curve = EncodeToCurveBabyJubJub();
    encode_to_curve.in <== in;
    out[0] <== encode_to_curve.out.x;
    out[1] <== encode_to_curve.out.y;
}

component main = EncodeToCurveBabyJubJubMain();
