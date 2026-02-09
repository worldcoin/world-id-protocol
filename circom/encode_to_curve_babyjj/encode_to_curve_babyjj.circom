pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";
include "poseidon2/poseidon2.circom";
include "circomlib/mux1.circom";
include "circomlib/babyjub.circom";
include "circomlib/comparators.circom";
include "circomlib/gates.circom";
include "inverse_or_zero/inverse_or_zero.circom";
include "quadratic_residue/quadratic_residue.circom";
include "sgn0/sgn0.circom";


// An implementation of hash_to_field based on https://www.rfc-editor.org/rfc/rfc9380.html.
// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
template HashToField() {
    signal input in;
    signal output out;

    component hasher = Poseidon2(3);
    // element 0 is the DS string "OPRF_HashToField_BabyJubJub"
    hasher.in <== [32627786498498119128812045057993354633158048678109587794777765218,in,0];
    // We return element 1; element 0 is the capacity of the sponge
    out <== hasher.out[1];
}

// Maps the input to a point on the Montgomery curve, without anyone knowing the DLOG of the curve point.
//
// Returns the s and t coordinates of the point on the Montgomery curve.
//
// let the Montgomery curve be defined by the equation K*t^2 = s^3 + J*s^2 + s.
// We follow the Elligator2 mapping as described in https://www.rfc-editor.org/rfc/rfc9380.html#name-elligator-2-method.
template MapToCurveElligator2() {
    signal input in;
    signal output out[2];

    // var j = 168698;
    var k = 1;
    // var c1 = j / k;
    // var c2 = (k*k).inverse();
    var c1 = 168698;
    var c2 = 1;

    var z = 5;
    signal tv1_0 <== z * (in * in);
    signal e <== IsZero()(tv1_0 + 1);

    signal tv1 <== Mux1()([tv1_0, 0], e);
    component x1_inv_zero = InverseOrZero();
    x1_inv_zero.in <== tv1 + 1;
    signal x1 <== -c1 * x1_inv_zero.inv;

    signal gx1_0 <== (x1 + c1) * x1;
    signal gx1 <== (gx1_0 + c2) * x1;
    signal x2 <== -x1 - c1;
    signal gx2 <== tv1 * gx1;
    signal e2 <== IsQuadraticResidueOrZero()(gx1);

    signal x <== Mux1()([x2,x1], e2);
    signal y2 <== Mux1()([gx2,gx1], e2);

    // Note: sqrt_unchecked(y2) may return either square root r or -r; it does not fix a sign.
    // We enforce a canonical choice for y via the additional constraint rather than relying on the function.
    // TODO: Consider folding this canonicalization into sqrt_unchecked so callers always receive the canonical root which we then of course have to constraint correctly.
    signal y <-- bbf_sqrt_unchecked(y2);
    y*y === y2;

    signal e3 <== Sgn0()(y);

    // assert that e2 and e3 are really booleans
    // this is just a runtime assertion and not a constraint
    assert(e2 == 0 || e2 == 1);
    assert(e3 == 0 || e3 == 1);
    signal xor <== XOR()(e2,e3);
    signal multiplication <== Mux1()([1,-1], xor);
    signal y_1 <== y * multiplication;

    out[0] <== x * k;
    out[1] <== y_1 * k;
}


// Converts a point from BabyJubJub in Montgomery form to Twisted Edwards form using the rational map.
//
// This is based on appendix D1 of https://www.rfc-editor.org/rfc/rfc9380.html.
//
// Let the twisted Edwards curve be defined by the equation a*v^2 + w^2 = 1 + d*v^2*w^2.
// let the Montgomery curve be defined by the equation K*t^2 = s^3 + J*s^2 + s, with
// J = 2 * (a + d) / (a - d)$ and $K = 4 / (a - d).
//
// For the concrete case of BabyJubJub, we have:
// - K = 1
// - J = 168698
// - a = 168700
// - d = 168696
//
// Input: (s, t), a point on the curve K * t^2 = s^3 + J * s^2 + s.
// Output: (v, w), a point on the equivalent twisted Edwards curve.
// (This function also handles exceptional cases where the point is at infinity correctly.)
template RationalMapMontToTwistedEdwardsBabyJubJub() {
    signal input in[2];
    signal output out[2];

    signal s <== in[0];
    signal t <== in[1];

    signal tv1 <== s + 1;
    signal tv2 <== InverseOrZero()(tv1 * t);
    signal v <== tv1 * tv2;
    signal w <== tv2 * t;

    signal tv11 <== s - 1;
    signal e <== IsZero()(tv2);
    out[0] <== s * v;
    out[1] <== Mux1()([w * tv11, 1], e);
}


// Maps the input to a point on the curve, without anyone knowing the DLOG of the curve point.
//
// This is based on map_to_curve from https://www.rfc-editor.org/rfc/rfc9380.html.
// We use section 6.8 ("Mappings for Twisted Edwards Curves") to map the input to a point on the curve.
// This internally uses a birationally equivalent Montgomery curve to perform the mapping, then uses a rational map to convert the point to the Edwards curve.
template MapToCurveTwistedEdwards() {
    signal input in;
    output BabyJubJubPoint() { twisted_edwards } out;

    signal ell2[2] <== MapToCurveElligator2()(in);
    signal outxy[2] <== RationalMapMontToTwistedEdwardsBabyJubJub()(ell2);
    // SAFETY: The output of the rational map from Mont to TE results in a point on the BJJ curve
    out.x <== outxy[0];
    out.y <== outxy[1];
}


// Performs cofactor clearing for BabyJubJub.
// The default method is simply to multiply by the cofactor, which is 8 for BabyJubJub.
template ClearCoFactorBabyJubJub() {
    input BabyJubJubPoint() { twisted_edwards } in;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    signal (double_x, double_y) <== BabyDbl()(in.x, in.y);
    signal (quadruple_x, quadruple_y) <== BabyDbl()(double_x, double_y);
    signal (eight_x, eight_y) <==  BabyDbl()(quadruple_x, quadruple_y);
    // SAFETY: Clearing the small-order terms of a point on the curve places it in the prime-order subgroup
    out.x <== eight_x;
    out.y <== eight_y;
}

// A curve encoding function that maps a field element to a point on the curve, based on https://www.rfc-editor.org/rfc/rfc9380.html#name-encoding-byte-strings-to-el.
//
// As mentioned in the RFC, this encoding is non uniformly random in E, as this can only hit about half of the of the curve points.
template EncodeToCurveBabyJubJub() {
    signal input in;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    signal u <== HashToField()(in);
    BabyJubJubPoint() { twisted_edwards } q <== MapToCurveTwistedEdwards()(u);
    out <== ClearCoFactorBabyJubJub()(q);
}
