// Constraint-optimized replacements for the oprf-nr BabyJubJub gadgets (measurement prototype).
// Montgomery addition is incomplete; like circomlib's EscalarMulAny, the accumulator starts at an
// offset point so honest inputs never hit the exceptional cases. Needs review before production use.
use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup, BabyJubJubScalarFieldElement};
use babyjubjub::hash_to_curve::encode;
use poseidon2::bn254::permutation;

global MONT_A: Field = 168698;
global DS_EDDSA: Field = 360302137480307891234917541314130533;
global EIGHT_INV: Field =
    2394026564107420727433200628387514462817212225638746351800188703329891451411;

struct M {
    u: Field,
    v: Field,
}
unconstrained fn div(a: Field, b: Field) -> Field {
    a / b
}
fn to_m(p: BabyJubJubPoint) -> M {
    let u = unsafe { div(1 + p.y(), 1 - p.y()) };
    assert(u * (1 - p.y()) == 1 + p.y());
    let v = unsafe { div(u, p.x()) };
    assert(v * p.x() == u);
    M { u, v }
}
fn from_m(p: M) -> BabyJubJubPoint {
    let x = unsafe { div(p.u, p.v) };
    assert(x * p.v == p.u);
    let y = unsafe { div(p.u - 1, p.u + 1) };
    assert(y * (p.u + 1) == p.u - 1);
    BabyJubJubPoint::new_unchecked(x, y)
}
fn m_add(p: M, q: M) -> M {
    let l = unsafe { div(q.v - p.v, q.u - p.u) };
    assert(l * (q.u - p.u) == q.v - p.v);
    let u3 = l * l - MONT_A - p.u - q.u;
    M { u: u3, v: l * (p.u - u3) - p.v }
}
fn m_dbl(p: M) -> M {
    let num = 3 * p.u * p.u + 2 * MONT_A * p.u + 1;
    let l = unsafe { div(num, 2 * p.v) };
    assert(l * 2 * p.v == num);
    let u3 = l * l - MONT_A - 2 * p.u;
    M { u: u3, v: l * (p.u - u3) - p.v }
}

/// `bits * p` (little-endian bits), Montgomery double-and-add with an offset accumulator.
pub fn mul_bits<let N: u32>(p: BabyJubJubPoint, bits: [bool; N]) -> BabyJubJubPoint {
    let offset = BabyJubJubPoint::generator();
    let mut d = to_m(p);
    let mut acc = to_m(offset);
    for i in 0..N {
        let s = m_add(acc, d);
        let b = bits[i] as Field;
        acc = M { u: acc.u + b * (s.u - acc.u), v: acc.v + b * (s.v - acc.v) };
        if i + 1 < N {
            d = m_dbl(d);
        }
    }
    from_m(acc).subtract(offset)
}

pub fn mul_base_field(p: BabyJubJubPoint, h: Field) -> BabyJubJubPoint {
    let bits: [bool; 254] = h.to_le_bits();
    mul_bits(p, bits)
}

unconstrained fn div_by_8(x: Field, y: Field) -> (Field, Field) {
    let q = BabyJubJubPoint::new_unchecked(x, y).scalar_mul_base_field(EIGHT_INV);
    (q.x(), q.y())
}

/// On-curve and prime-order-subgroup check: the group is cyclic of order 8r, so the subgroup is
/// exactly the set of points 8Q.
pub fn point_in_subgroup(x: Field, y: Field) -> BabyJubJubPoint {
    let p = BabyJubJubPoint::new(x, y);
    let (qx, qy) = unsafe { div_by_8(x, y) };
    let e = BabyJubJubPoint::new(qx, qy).double().double().double();
    assert((e.x() == x) & (e.y() == y), "Point is not in the correct subgroup");
    p
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
    let p = encode(client_input);
    mul_bits(BabyJubJubPoint::new_unchecked(p.x(), p.y()), bits)
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
    let encoded = encode(client_input);
    let b = mul_bits(
        BabyJubJubPoint::new_unchecked(encoded.x(), encoded.y()),
        beta_bits,
    );
    let response = point_in_subgroup(response_x, response_y);
    let c = mul_bits(response, beta_bits);

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
