/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/
pragma circom 2.0.0;

// This file is copied from https://github.com/iden3/circomlib/blob/master/circuits/eddsaposeidon.circom and adapted to use Poseidon2 instead of Poseidon and use a more standard cofactored verification.

include "poseidon2/poseidon2.circom";
include "babyjubjub/babyjubjub.circom";

template EdDSAPoseidon2Verifier() {
    signal input Ax;
    signal input Ay;

    signal input S;
    signal input Rx;
    signal input Ry;

    signal input M;

    var i;

    // Ensure S < Subgroup Order
    component s_range = BabyJubJubIsInFr();
    s_range.in <== S;

    // Calculate the h = H(R,A, msg)
    component hash = Poseidon2(8);
    hash.in[0] <== 360302137480307891234917541314130533; // Domain separator in capacity element b"EdDSA Signature"
    hash.in[1] <== Rx;
    hash.in[2] <== Ry;
    hash.in[3] <== Ax;
    hash.in[4] <== Ay;
    hash.in[5] <== M;
    hash.in[6] <== 0;
    hash.in[7] <== 0;

    // We check that R is on the curve.
    // This is not strictly necessary for security, but since it only adds 3 constraints we do it anyway.
    // We do not require R to be in the correct subgroup, since it is only used in Twisted Edwards additions.
    BabyJubJubPoint { twisted_edwards } R_p <== BabyJubJubCheck()(Rx, Ry);
    // We check that A is on the curve and in the correct subgroup.
    BabyJubJubPoint { twisted_edwards_in_subgroup } A_p <== BabyJubJubCheckAndSubgroupCheck()(Ax, Ay);
    // We check that A is not zero.
    component isZero = IsZero();
    isZero.in <== Ax;
    isZero.out === 0;

    // Calculate second part of the right side:  right2 = h*A
    BabyJubJubBaseField() h_f;
    h_f.f <== hash.out[1];
    // Precondition: A is in the correct subgroup, checked above.
    component mulAny = BabyJubJubScalarMulBaseField();
    mulAny.e <== h_f;
    mulAny.p <== A_p;

    // Compute the right side: right =  R + right2
    component addRight = BabyAdd();
    addRight.x1 <== Rx;
    addRight.y1 <== Ry;
    addRight.x2 <== mulAny.out.x;
    addRight.y2 <== mulAny.out.y;

    // Calculate left side of equation left = S*B
    component mulFix = BabyJubJubScalarGeneratorBits();
    mulFix.e <== s_range.out_bits;

    // compute v = s*B - R - h*A = s*B - (R + h*A)
    component v = BabyAdd();
    v.x1 <== mulFix.out.x;
    v.y1 <== mulFix.out.y;
    v.x2 <== -addRight.xout;
    v.y2 <== addRight.yout;

    // Multiply by 8 by adding it 3 times.  This also ensure that the result is in
    // the subgroup.
    component dbl1 = BabyDbl();
    dbl1.x <== v.xout;
    dbl1.y <== v.yout;
    component dbl2 = BabyDbl();
    dbl2.x <== dbl1.xout;
    dbl2.y <== dbl1.yout;
    component dbl3 = BabyDbl();
    dbl3.x <== dbl2.xout;
    dbl3.y <== dbl2.yout;

    // Do the comparison 8*v == Identity;
    dbl3.xout === 0;
    dbl3.yout === 1;
}
