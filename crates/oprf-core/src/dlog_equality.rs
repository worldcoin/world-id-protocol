use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use num_bigint::BigUint;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DLogEqualityProof {
    pub e: BaseField,
    pub s: ScalarField, // The verifier checks it fits in the base field to prevent malleability attacks.
}

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;

impl DLogEqualityProof {
    const DLOG_DS: &[u8] = b"DLOG Equality Proof";

    // Returns the domain separator for the query finalization as a field element
    fn get_dlog_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::DLOG_DS)
    }

    /// Creates a proof which shows that C=x*B and A=x*D share the same dlog x. This proof can be verified using B, C, and A=x*D. D is currently hard coded as the generator of the group.
    pub fn proof(b: Affine, x: ScalarField, rng: &mut (impl CryptoRng + Rng)) -> Self {
        let k = ScalarField::rand(rng);
        let r1 = (Affine::generator() * k).into_affine();
        let r2 = (b * k).into_affine();
        let a = (Affine::generator() * x).into_affine();
        let c = (b * x).into_affine();
        let d = Affine::generator();
        let e = challenge_hash(a, b, c, d, r1, r2);

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e_ = convert_base_to_scalar(e);
        let s = k + e_ * x;
        DLogEqualityProof { e, s }
    }

    /// Takes the proof e,s and verifies that A=x*D and C=x*B have the same dlog x, given A,B,C,D.
    pub fn verify(&self, a: Affine, b: Affine, c: Affine, d: Affine) -> bool {
        // All points need to be valid curve elements.
        if [a, b, c, d]
            .iter()
            .any(|p| !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve())
        {
            return false;
        }
        if [a, b, c, d].iter().any(|p| p.is_zero()) {
            return false;
        }

        // The following check is required to prevent malleability of the proofs by using different s, such as s + p.
        // In Rust this check is not required since self.s is a ScalarField element already, but we keep it to have the same implementation as in circom (where it is required).
        let s_biguint: BigUint = self.s.into();
        if s_biguint >= ScalarField::MODULUS.into() {
            return false;
        }

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e = convert_base_to_scalar(self.e);

        let r_1 = d * self.s - a * e;
        if r_1.is_zero() {
            return false;
        }
        let r_2 = b * self.s - c * e;
        if r_2.is_zero() {
            return false;
        }
        let e = challenge_hash(a, b, c, d, r_1.into_affine(), r_2.into_affine());
        e == self.e
    }
}

pub(crate) fn challenge_hash(
    a: Affine,
    b: Affine,
    c: Affine,
    d: Affine,
    r1: Affine,
    r2: Affine,
) -> BaseField {
    let poseidon = Poseidon2::<_, 16, 5>::default();
    let hash_input = [
        DLogEqualityProof::get_dlog_ds(), // Domain separator in capacity of hash
        a.x,
        a.y,
        b.x,
        b.y,
        c.x,
        c.y,
        d.x,
        d.y,
        r1.x,
        r1.y,
        r2.x,
        r2.y,
        BaseField::zero(),
        BaseField::zero(),
        BaseField::zero(),
    ];
    poseidon.permutation(&hash_input)[1] // output first state element as hash output
}

// This is just a modular reduction. We show in the docs why this does not introduce a bias when applied to a uniform element of the base field.
pub(crate) fn convert_base_to_scalar(f: BaseField) -> ScalarField {
    let bytes = f.into_bigint().to_bytes_le();
    ScalarField::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_dlog_equality() {
        let mut rng = rand::thread_rng();
        let x = ScalarField::rand(&mut rng);
        let d = Affine::generator();
        let a = (d * x).into_affine();
        let b = Affine::rand(&mut rng);
        let c = (b * x).into_affine();

        let proof = DLogEqualityProof::proof(b, x, &mut rng);
        assert!(proof.verify(a, b, c, d), "valid proof should verify");
        let b2 = Affine::rand(&mut rng);
        let invalid_proof = DLogEqualityProof::proof(b2, x, &mut rng);
        assert!(
            !invalid_proof.verify(a, b, c, d),
            "invalid proof should not verify"
        );
    }
}
