pragma circom 2.2.2;

include "circomlib/bitify.circom";

/// Computes the `sgn0` function for a field element, based on the definition in https://www.rfc-editor.org/rfc/rfc9380.html#name-the-sgn0-function.
// It bit-decomposes the input element and returns the lsb. 
template Sgn0() {
    signal input in;
    signal output out;

    signal bits[254] <== Num2Bits_strict()(in);
    out <== bits[0];
}
