use ruint::aliases::U256;

pub mod nullifier;
pub mod query;

#[inline(always)]
pub(crate) fn fq_to_u256_vec(f: ark_babyjubjub::Fq) -> Vec<U256> {
    vec![f.into()]
}

#[inline(always)]
pub(crate) fn fq_seq_to_u256_vec(fs: &[ark_babyjubjub::Fq]) -> Vec<U256> {
    fs.iter().copied().map(|x| x.into()).collect()
}

#[inline(always)]
pub(crate) fn fr_to_u256_vec(f: ark_babyjubjub::Fr) -> Vec<U256> {
    vec![f.into()]
}

#[inline(always)]
pub(crate) fn affine_to_u256_vec(p: ark_babyjubjub::EdwardsAffine) -> Vec<U256> {
    vec![p.x.into(), p.y.into()]
}

#[inline(always)]
pub(crate) fn affine_seq_to_u256_vec(ps: &[ark_babyjubjub::EdwardsAffine]) -> Vec<U256> {
    ps.iter()
        .copied()
        .flat_map(|p| [p.x.into(), p.y.into()])
        .collect()
}
