// Constraint-optimized replacements for the oprf-nr BabyJubJub gadgets (measurement prototype).
// Montgomery addition is incomplete: every addition proves its two inputs have distinct u, so an
// input that collides with the offset accumulator fails to prove instead of freeing the slope.
use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup, BabyJubJubScalarFieldElement};
use babyjubjub::hash_to_curve::encode;
use poseidon2::bn254::permutation;

global MONT_A: Field = 168698;
global DS_EDDSA: Field = 360302137480307891234917541314130533;
global EIGHT_INV: Field =
    2394026564107420727433200628387514462817212225638746351800188703329891451411;

/// The BabyJubJub generator in Montgomery coordinates, the ladder's offset accumulator.
global OFFSET_U: Field =
    7117928050407583618111176421555214756675765419608405867398403713213306743542;
global OFFSET_V: Field =
    14577268218881899420966779687690205425227431577728659819975198491127179315626;

struct M {
    u: Field,
    v: Field,
}

/// `bits * p` (little-endian bits), Montgomery double-and-add with an offset accumulator.
///
/// `p` must be in the prime-order subgroup: its multiples then never have order 2, so every
/// doubling slope is determined. Inputs where an addition degenerates (`p = G` at the first
/// step, or a later collision with the accumulator) fail to prove.
///
/// One unconstrained call computes every hint of the ladder; per-step hint calls dominate
/// witness generation and blow up the ACIR program.
pub fn mul_bits<let N: u32>(p: BabyJubJubPointInSubgroup, bits: [bool; N]) -> BabyJubJubPoint {
    // Safety: each hint is checked below by the equation that defines it.
    let (u0, v0, add_slopes, add_invs, dbl_slopes, acc_v_inv, x, y) =
        unsafe { ladder_hints(p.x(), p.y(), bits) };
    assert(u0 * (1 - p.y()) == 1 + p.y());
    assert(v0 * p.x() == u0);

    let mut d = M { u: u0, v: v0 };
    let mut acc = M { u: OFFSET_U, v: OFFSET_V };
    for i in 0..N {
        // A nonzero `d.u - acc.u` makes the slope unique; without it any slope satisfies `d = acc`.
        assert(add_invs[i] * (d.u - acc.u) == 1, "exceptional Montgomery addition");
        let l = add_slopes[i];
        assert(l * (d.u - acc.u) == d.v - acc.v);
        let u3 = l * l - MONT_A - acc.u - d.u;
        let sum = M { u: u3, v: l * (acc.u - u3) - acc.v };
        let b = bits[i] as Field;
        acc = M { u: acc.u + b * (sum.u - acc.u), v: acc.v + b * (sum.v - acc.v) };

        let ld = dbl_slopes[i];
        assert(ld * 2 * d.v == 3 * d.u * d.u + 2 * MONT_A * d.u + 1);
        let u4 = ld * ld - MONT_A - 2 * d.u;
        d = M { u: u4, v: ld * (d.u - u4) - d.v };
    }

    assert(acc_v_inv * acc.v == 1, "exceptional Montgomery accumulator");
    assert(x * acc.v == acc.u);
    assert(y * (acc.u + 1) == acc.u - 1);
    BabyJubJubPoint::new_unchecked(x, y).subtract(BabyJubJubPoint::generator())
}

/// The Montgomery form of `p`, every add slope with the inverse of its u-difference, every
/// double slope, and the final accumulator's v inverse and Edwards form. The last doubling is
/// unused but computed so every hint is constrained. Degenerate steps yield `0` hints, which the
/// constraints reject.
unconstrained fn ladder_hints<let N: u32>(
    px: Field,
    py: Field,
    bits: [bool; N],
) -> (Field, Field, [Field; N], [Field; N], [Field; N], Field, Field, Field) {
    let u0 = inv_or_zero(1 - py) * (1 + py);
    let v0 = inv_or_zero(px) * u0;
    let mut d = M { u: u0, v: v0 };
    let mut acc = M { u: OFFSET_U, v: OFFSET_V };
    let mut add_slopes = [0; N];
    let mut add_invs = [0; N];
    let mut dbl_slopes = [0; N];
    for i in 0..N {
        let inv = inv_or_zero(d.u - acc.u);
        add_invs[i] = inv;
        let l = (d.v - acc.v) * inv;
        add_slopes[i] = l;
        if bits[i] {
            let u3 = l * l - MONT_A - acc.u - d.u;
            acc = M { u: u3, v: l * (acc.u - u3) - acc.v };
        }
        let ld = (3 * d.u * d.u + 2 * MONT_A * d.u + 1) * inv_or_zero(2 * d.v);
        dbl_slopes[i] = ld;
        let u4 = ld * ld - MONT_A - 2 * d.u;
        d = M { u: u4, v: ld * (d.u - u4) - d.v };
    }
    let acc_v_inv = inv_or_zero(acc.v);
    (
        u0, v0, add_slopes, add_invs, dbl_slopes, acc_v_inv, acc.u * acc_v_inv,
        (acc.u - 1) * inv_or_zero(acc.u + 1),
    )
}

unconstrained fn inv_or_zero(x: Field) -> Field {
    if x == 0 {
        0
    } else {
        1 / x
    }
}

pub fn mul_base_field(p: BabyJubJubPointInSubgroup, h: Field) -> BabyJubJubPoint {
    let bits: [bool; 254] = h.to_le_bits();
    mul_bits(p, bits)
}

unconstrained fn div_by_8(x: Field, y: Field) -> (Field, Field) {
    let q = BabyJubJubPoint::new_unchecked(x, y).scalar_mul_base_field(EIGHT_INV);
    (q.x(), q.y())
}

/// On-curve and prime-order-subgroup check: the group is cyclic of order 8r, so the subgroup is
/// exactly the set of points 8Q.
pub fn point_in_subgroup(x: Field, y: Field) -> BabyJubJubPointInSubgroup {
    let p = BabyJubJubPoint::new(x, y);
    // Safety: Q is checked by recomputing 8Q.
    let (qx, qy) = unsafe { div_by_8(x, y) };
    let e = BabyJubJubPoint::new(qx, qy).double().double().double();
    assert((e.x() == x) & (e.y() == y), "Point is not in the correct subgroup");
    BabyJubJubPointInSubgroup::from_point_unchecked(p)
}

fn generator_mul(s: BabyJubJubScalarFieldElement) -> BabyJubJubPoint {
    let g = BabyJubJubPointInSubgroup::generator_scalar_mul(s);
    BabyJubJubPoint::new_unchecked(g.x(), g.y())
}

/// Drop-in for `eddsa_poseidon2::verify_eddsa_poseidon2` (cofactored).
pub fn verify_eddsa(ax: Field, ay: Field, s: Field, rx: Field, ry: Field, message: Field) -> bool {
    let a = point_in_subgroup(ax, ay);
    assert(a.is_not_identity(), "Public key cannot be identity");
    let r = BabyJubJubPoint::new(rx, ry);
    let h = permutation::t8([DS_EDDSA, rx, ry, ax, ay, message, 0, 0])[1];
    let right = r.add(mul_base_field(a, h));
    let left = generator_mul(BabyJubJubScalarFieldElement::new(s));
    left.subtract(right).double().double().double().is_identity()
}

/// Drop-in for `oprf::blinded_query::blinded_query`.
pub fn blinded_query(beta: Field, client_input: Field) -> BabyJubJubPoint {
    assert(beta != 0, "Beta cannot be zero");
    let bits = BabyJubJubScalarFieldElement::new(beta).to_le_bits();
    mul_bits(encode(client_input), bits)
}

/// Drop-in for `oprf::oprf_output::verified_oprf`.
pub fn verified_oprf(
    beta: Field,
    oprf_pk_x: Field,
    oprf_pk_y: Field,
    dlog_e: Field,
    dlog_s: Field,
    response_x: Field,
    response_y: Field,
    client_input: Field,
    ds_dlog: Field,
    ds_out: Field,
) -> Field {
    assert(beta != 0, "Beta cannot be zero");
    let beta_bits = BabyJubJubScalarFieldElement::new(beta).to_le_bits();
    let a = point_in_subgroup(oprf_pk_x, oprf_pk_y);
    // `b` and `c` are multiples of subgroup points, so they are in the subgroup too.
    let b =
        BabyJubJubPointInSubgroup::from_point_unchecked(mul_bits(encode(client_input), beta_bits));
    let response = point_in_subgroup(response_x, response_y);
    let c = BabyJubJubPointInSubgroup::from_point_unchecked(mul_bits(response, beta_bits));

    assert(a.is_not_identity() & b.is_not_identity() & c.is_not_identity(), "identity point");
    let s_el = BabyJubJubScalarFieldElement::new(dlog_s);
    let r1 = generator_mul(s_el).subtract(mul_base_field(a, dlog_e));
    let r2 = mul_bits(b, s_el.to_le_bits()).subtract(mul_base_field(c, dlog_e));
    assert(r1.is_not_identity() & r2.is_not_identity(), "Computed points cannot be identity");
    let g = BabyJubJubPoint::generator();
    let challenge = permutation::t16([
        ds_dlog, a.x(), a.y(), b.x(), b.y(), c.x(), c.y(), g.x(), g.y(), r1.x(), r1.y(), r2.x(),
        r2.y(), 0, 0, 0,
    ])[1];
    assert(challenge == dlog_e, "Challenge verification failed");
    std::hash::poseidon2_permutation([ds_out, client_input, response.x(), response.y()])[1]
}

#[test]
fn test_eddsa_vectors() {
    assert(verify_eddsa(
        15861662102942198476185518224532077347254150735350796263259682790715259346390,
        17622332940847650587004774926435083207962382856110852169511204932927794212320,
        2128104906629434075529508057546284580247227319347477887390422344724817923329,
        19090079173373584153996824137084726661643725553797485823319088208683554498717,
        3643574957097202527589616469273298197083911730855228311907034680488748021268,
        3126080974277891902445700130528654565374341115115698716199527644337840721369,
    ));
    assert(
        !verify_eddsa(
            15861662102942198476185518224532077347254150735350796263259682790715259346390,
            17622332940847650587004774926435083207962382856110852169511204932927794212320,
            2128104906629434075529508057546284580247227319347477887390422344724817923329,
            19090079173373584153996824137084726661643725553797485823319088208683554498717,
            3643574957097202527589616469273298197083911730855228311907034680488748021268,
            3126080974277891902445700130528654565374341115115698716199527644337840721370,
        ),
    );
}

#[test]
fn test_blinded_query_vector() {
    let b = blinded_query(
        1219447978145766874721695300216900264892278162307712369438981445355514609028,
        387242419257851558984914892096106188402994395767663340643461644969954908901,
    );
    assert_eq(b.x(), 9674018812144873985515234638873635008708834681175738612597888298086191498827);
    assert_eq(b.y(), 18818965079786157878748649151755578492493325229415754584538271947197071123195);
}

#[test(should_fail_with = "Point is not in the correct subgroup")]
fn test_rejects_small_order_point() {
    let _ = point_in_subgroup(0, -1);
}

#[test(should_fail_with = "exceptional Montgomery addition")]
fn test_rejects_input_colliding_with_the_offset() {
    let g = BabyJubJubPointInSubgroup::generator();
    let _ = mul_bits(g, [true, false, true]);
}

#[test]
fn test_mul_bits_matches_the_library() {
    let p = encode(42);
    let bits: [bool; 251] = BabyJubJubScalarFieldElement::new(123456789).to_le_bits();
    let expected = p.scalar_mul_bits(bits);
    let got = mul_bits(p, bits);
    assert_eq(got.x(), expected.x());
    assert_eq(got.y(), expected.y());
}
