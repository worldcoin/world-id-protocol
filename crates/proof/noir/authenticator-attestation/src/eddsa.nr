// EdDSA signature verification over BabyJubJub with Poseidon2 as the
// challenge hash, matching TACEO's `eddsa-babyjubjub` Rust crate.
//
// TODO: replace with the upstream package once TACEO publishes it for oprf-nr.
use babyjubjub::{BabyJubJubPoint, BabyJubJubScalarFieldElement};
use poseidon2::bn254::permutation;

/// Domain separator for EdDSA signatures: `be_bytes("EdDSA Signature")`.
global DOMAIN_SEPARATOR: Field = 360302137480307891234917541314130533;

/// Verifies an EdDSA-Poseidon2 signature.
///
/// Verification equation (cofactored): `8*(S*G - R - h*A) == identity`,
/// where `h = Poseidon2_t8(domain_separator, Rx, Ry, Ax, Ay, M, 0, 0)[1]`.
pub fn verify_eddsa_poseidon2(
    pub_key_x: Field,
    pub_key_y: Field,
    signature_s: Field,
    signature_r: [Field; 2],
    message: Field,
) -> bool {
    // 1. S must be in the BabyJubJub scalar field (rejects malleable S).
    let s = BabyJubJubScalarFieldElement::new(signature_s);

    // 2. A must be on-curve (checked by `new`), in the prime-order subgroup
    //    and not the identity.
    let a_point = BabyJubJubPoint::new(pub_key_x, pub_key_y);
    assert(a_point.check_sub_group(), "Public key must be in subgroup");
    assert(a_point.is_not_identity(), "Public key cannot be identity");

    // 3. R must be on-curve (checked by `new`).
    let r_point = BabyJubJubPoint::new(signature_r[0], signature_r[1]);

    // 4. h = Poseidon2(DS, Rx, Ry, Ax, Ay, M, 0, 0)
    let hash_state = permutation::t8([
        DOMAIN_SEPARATOR,
        signature_r[0],
        signature_r[1],
        pub_key_x,
        pub_key_y,
        message,
        0,
        0,
    ]);
    let hash = hash_state[1];

    // 5. v = S*G - (R + h*A)
    let right = r_point.add(a_point.scalar_mul_base_field(hash));
    let left = BabyJubJubPoint::generator_scalar_mul(s);
    let v = left.subtract(right);

    // 6. Cofactored check: 8*v == identity
    v.double().double().double().is_identity()
}
