use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use rand::{Rng, seq::IteratorRandom};

/// Share
#[allow(unused)]
pub(crate) fn share<F: PrimeField, R: Rng>(
    secret: F,
    num_shares: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<F> {
    let mut shares = Vec::with_capacity(num_shares);
    let mut coeffs = Vec::with_capacity(degree + 1);
    coeffs.push(secret);
    for _ in 0..degree {
        coeffs.push(F::rand(rng));
    }
    for i in 1..=num_shares {
        let share = evaluate_poly(&coeffs, F::from(i as u64));
        shares.push(share);
    }
    shares
}

/// Compute the lagrange coeffs from given party indices
pub fn lagrange_from_coeff<F: PrimeField>(coeffs: &[usize]) -> Vec<F> {
    let num = coeffs.len();
    let mut res = Vec::with_capacity(num);
    for i in coeffs.iter() {
        let mut num = F::one();
        let mut den = F::one();
        let i_ = F::from(*i as u64);
        for j in coeffs.iter() {
            if i != j {
                let j_ = F::from(*j as u64);
                num *= j_;
                den *= j_ - i_;
            }
        }
        let res_ = num * den.inverse().unwrap();
        res.push(res_);
    }
    res
}

/// Evaluate the poly at the given x
pub(crate) fn evaluate_poly<F: PrimeField>(poly: &[F], x: F) -> F {
    debug_assert!(!poly.is_empty());
    let mut iter = poly.iter().rev();
    let mut eval = iter.next().unwrap().to_owned();
    for coeff in iter {
        eval *= x;
        eval += coeff;
    }
    eval
}

/// Reconstruct the from its shares and lagrange coefficients.
pub fn reconstruct<F: PrimeField>(shares: &[F], lagrange: &[F]) -> F {
    debug_assert_eq!(shares.len(), lagrange.len());
    let mut res = F::zero();
    for (s, l) in shares.iter().zip(lagrange.iter()) {
        res += *s * l
    }

    res
}

/// Reconstructs a curve point from its Shamir shares and lagrange coefficients.
pub(crate) fn reconstruct_point<C: CurveGroup>(
    shares: &[C::Affine],
    lagrange: &[C::ScalarField],
) -> C {
    debug_assert_eq!(shares.len(), lagrange.len());
    C::msm_unchecked(shares, lagrange)
}

#[allow(unused)]
pub(crate) fn reconstruct_random_shares<F: PrimeField, R: Rng>(
    shares: &[F],
    degree: usize,
    rng: &mut R,
) -> F {
    let num_parties = shares.len();
    let parties = (1..=num_parties).choose_multiple(rng, degree + 1);
    let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
    let lagrange = lagrange_from_coeff(&parties);
    reconstruct(&shares, &lagrange)
}

#[allow(unused)]
pub(crate) fn reconstruct_random_pointshares<C: CurveGroup, R: Rng>(
    shares: &[C],
    degree: usize,
    rng: &mut R,
) -> C {
    let num_parties = shares.len();
    let parties = (1..=num_parties).choose_multiple(rng, degree + 1);
    // maybe sufficient to into_affine in the following map
    let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
    let shares = C::batch_convert_to_mul_base(&shares);
    let lagrange = lagrange_from_coeff(&parties);
    reconstruct_point(&shares, &lagrange)
}
