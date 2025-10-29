use crate::dlog_equality::DLogEqualityProof;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDLogEqualityCommitments {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) c: Affine, // The share of the actual result C=B*x
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) r1: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) r2: Affine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLogEqualityCommitments {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) c: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) r1: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) r2: Affine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLogEqualityProofShare {
    // The share of the response s
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_scalar")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_scalar")]
    pub(crate) s: ScalarField,
}

/// The internal storage of a party in a distributed DlogEqualityProof protocol.
///
/// This is not `Clone` because it contains secret randomness that may only be used once. We also don't implement `Debug` so we do don't print it by accident.
/// The `challenge` method consumes the session.
#[derive(ZeroizeOnDrop)]
pub struct DLogEqualitySession {
    k: ScalarField,
    blinded_query: Affine,
}

type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

impl DLogEqualitySession {
    /// Computes C=B*x_share and commitments to a random value k_share, which will be the share of the randomness used in the DlogEqualityProof.
    /// The result is meant to be sent to one accumulating party (e.g., the verifier) who combines all the shares of all parties and creates the challenge hash.
    pub fn partial_commitments(
        b: Affine,
        x_share: ScalarField,
        rng: &mut (impl CryptoRng + Rng),
    ) -> (Self, PartialDLogEqualityCommitments) {
        let k_share = ScalarField::rand(rng);
        let r1 = (Affine::generator() * k_share).into_affine();
        let r2 = (b * k_share).into_affine();
        let c_share = (b * x_share).into_affine();

        let comm = PartialDLogEqualityCommitments { c: c_share, r1, r2 };

        let session = DLogEqualitySession {
            k: k_share,
            blinded_query: b,
        };

        (session, comm)
    }

    /// Finalizes a proof share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    pub fn challenge(
        self,
        x_share: ScalarField,
        a: Affine,
        challenge_input: DLogEqualityCommitments,
    ) -> DLogEqualityProofShare {
        // Recompute the challenge hash to ensure the challenge is well-formed.
        let d = Affine::generator();
        let e = crate::dlog_equality::challenge_hash(
            a,
            self.blinded_query,
            challenge_input.c,
            d,
            challenge_input.r1,
            challenge_input.r2,
        );
        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e_ = crate::dlog_equality::convert_base_to_scalar(e);
        DLogEqualityProofShare {
            s: self.k + e_ * x_share,
        }
    }
}

impl DLogEqualityCommitments {
    pub fn new(c: Affine, r1: Affine, r2: Affine) -> Self {
        DLogEqualityCommitments { c, r1, r2 }
    }
    /// The accumulating party (e.g., the verifier) combines all the shares of all parties.
    /// The returned points are the combined commitments C, R1, R2.
    pub fn combine_commitments(commitments: &[PartialDLogEqualityCommitments]) -> Self {
        let mut c = Projective::zero();
        let mut r1 = Projective::zero();
        let mut r2 = Projective::zero();

        for comm in commitments {
            c += comm.c;
            r1 += comm.r1;
            r2 += comm.r2;
        }

        let c = c.into_affine();
        let r1 = r1.into_affine();
        let r2 = r2.into_affine();

        DLogEqualityCommitments { c, r1, r2 }
    }

    pub fn combine_proofs(
        self,
        proofs: &[DLogEqualityProofShare],
        a: Affine,
        b: Affine,
    ) -> DLogEqualityProof {
        let mut s = ScalarField::zero();
        for proof in proofs {
            s += proof.s;
        }

        let d = Affine::generator();
        let e = crate::dlog_equality::challenge_hash(a, b, self.c, d, self.r1, self.r2);

        DLogEqualityProof { e, s }
    }

    /// Returns the combined blinded response C=B*x.
    pub fn blinded_response(&self) -> Affine {
        self.c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_distributed_dlog_equality(num_parties: usize) {
        let mut rng = rand::thread_rng();

        // Random x shares
        let x_shares = (0..num_parties)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();

        // Combine x shares
        let x = x_shares.iter().fold(ScalarField::zero(), |acc, x| acc + x);

        // Create public keys
        let public_key = (Affine::generator() * x).into_affine();
        let public_key_ = x_shares
            .iter()
            .map(|x| (Affine::generator() * x).into_affine())
            .fold(Projective::zero(), |acc, x| acc + x)
            .into_affine();
        assert_eq!(public_key, public_key_);

        // Crete session
        let b = Affine::rand(&mut rng);

        // 1) Client requests commitments from all servers
        let mut sessions = Vec::with_capacity(num_parties);
        let mut commitments = Vec::with_capacity(num_parties);
        for x_ in x_shares.iter().cloned() {
            let (session, comm) = DLogEqualitySession::partial_commitments(b, x_, &mut rng);
            sessions.push(session);
            commitments.push(comm);
        }

        // 2) Client accumulates commitments and creates challenge
        let challenge = DLogEqualityCommitments::combine_commitments(&commitments);
        let c = challenge.blinded_response();

        // 3) Client challenges all servers
        let mut proofs = Vec::with_capacity(num_parties);
        for (session, x_) in sessions.into_iter().zip(x_shares.iter().cloned()) {
            let proof = session.challenge(x_, public_key, challenge.to_owned());
            proofs.push(proof);
        }

        // 4) Client combines all proofs
        let proof = challenge.combine_proofs(&proofs, public_key, b);

        // Verify the result and the proof
        let d = Affine::generator();
        assert_eq!(c, b * x, "Result must be correct");
        assert!(
            proof.verify(public_key, b, c, d),
            "valid proof should verify"
        );
    }

    #[test]
    fn test_distributed_dlog_equality_3_parties() {
        test_distributed_dlog_equality(3);
    }

    #[test]
    fn test_distributed_dlog_equality_30_parties() {
        test_distributed_dlog_equality(30);
    }
}
