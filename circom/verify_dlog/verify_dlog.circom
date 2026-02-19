pragma circom 2.2.2;

include "poseidon2/poseidon2.circom";
include "babyjubjub/babyjubjub.circom";

// Poseidon sponge construction by hand to compute the challenge point e. We use state size 4 with capacity 1 and absorb all provided points and squeeze once. The challenge we output is the first element not counting the capacity from the squeeze.
template ComputeChallengeHash() {
    input BabyJubJubPoint() a;
    input BabyJubJubPoint() b;
    input BabyJubJubPoint() c;
    input BabyJubJubPoint() r1;
    input BabyJubJubPoint() r2;
    output signal challenge;

    component poseidon = Poseidon2(16);
    poseidon.in[0] <== 1523098184080632582082867317389990410064981862; // Domain separator in capacity element b"DLOG Equality Proof"
    poseidon.in[1] <== a.x;
    poseidon.in[2] <== a.y;
    poseidon.in[3] <== b.x;
    poseidon.in[4] <== b.y;
    poseidon.in[5] <== c.x;
    poseidon.in[6] <== c.y;
    poseidon.in[7] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553; // BabyJubJub base point x
    poseidon.in[8] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203; // BabyJubJub base point y
    poseidon.in[9] <== r1.x;
    poseidon.in[10] <== r1.y;
    poseidon.in[11] <== r2.x;
    poseidon.in[12] <== r2.y;
    poseidon.in[13] <== 0;
    poseidon.in[14] <== 0;
    poseidon.in[15] <== 0;
    challenge <== poseidon.out[1];
}

// This template takes a Dlog equality proof (= Chaum-Pedersen proof) e,s and verifies that A=x*D and C=x*B have the same discrete logarithm x, given A,B,C. D is currently hard coded as the generator of the group.
// Preconditions: A is a public input, which is checked outside of the circuit to be on the curve and in the correct subgroup.
template VerifyDlog() {
    input BabyJubJubBaseField() e;
    input signal s;
    input signal a[2];
    input signal b[2];
    input signal c[2];

    // Point A is public input. This means we don't necessarily need to check this inside the circuit, but can delegate that to the verifier in Rust land.
    BabyJubJubPoint { twisted_edwards } a_p_check <== BabyJubJubCheck()(a[0], a[1]);
    // SAFETY: Point A has been checked to be on the curve and in the correct subgroup outside of the circuit.
    BabyJubJubPoint { twisted_edwards_in_subgroup } a_p <== a_p_check;
    // check that B and C are on the correct subgroup - we don't need to check A, as this is a public point and we expect the verifier to check that in Rust land.
    BabyJubJubPoint { twisted_edwards_in_subgroup } b_p <== BabyJubJubCheckAndSubgroupCheck()(b[0], b[1]);
    BabyJubJubPoint { twisted_edwards_in_subgroup } c_p <== BabyJubJubCheckAndSubgroupCheck()(c[0], c[1]);

    // check if not the identity
    BabyJubJubCheckNotIdentity()(a_p);
    BabyJubJubCheckNotIdentity()(b_p);
    BabyJubJubCheckNotIdentity()(c_p);

    // Check that proof.s is in field Fq. This check is required to prevent malleability of the proof by using different s, such as s + q
    // Fq has 251 bits, therefore we call LessThan with 251
    component s_range = BabyJubJubIsInFr();
    s_range.in <== s;
    signal s_f[251] <== s_range.out_bits;

    // The Rust implementation now converts e to Fr by doing a modulo reduction. We don't do this here because this is rather expensive. Therefore, we perform the segmentmul with 3 bits extra work, but the added constraints there are cheaper than doing the mod reduction.

    // compute
    // G * s - a * e
    // Preconditions: a_p is on the curve and in the correct subgroup, checked above
    BabyJubJubPoint() lhs_r1 <== BabyJubJubScalarGeneratorBits()(s_f);
    BabyJubJubPoint() rhs_r1 <== BabyJubJubScalarMulBaseField()(e, a_p);

    BabyJubJubPoint() r1 <== BabyJubJubSub()(lhs_r1, rhs_r1);
    // check that r1 is not the identity element
    BabyJubJubCheckNotIdentity()(r1);

    // compute
    // b * s - c * e
    // Preconditions: b_p and c_p are on the curve and in the correct subgroup, checked above
    BabyJubJubPoint() lhs_r2 <== BabyJubJubScalarMulBits()(s_f, b_p);
    BabyJubJubPoint() rhs_r2 <== BabyJubJubScalarMulBaseField()(e, c_p);

    BabyJubJubPoint() r2 <== BabyJubJubSub()(lhs_r2, rhs_r2);
    // check that r1 is not the identity element
    BabyJubJubCheckNotIdentity()(r2);

    // recompute the challenge hash
    signal challenge <== ComputeChallengeHash()(a_p,b_p,c_p,r1,r2);
    challenge === e.f;
}
