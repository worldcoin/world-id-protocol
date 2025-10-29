use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand, Zero};
use itertools::izip;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};

use crate::shamir;

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

pub struct KeyGenPoly {
    poly: Vec<ScalarField>,
    comm_share: Affine,
    comm_coeffs: BaseField,
}

impl KeyGenPoly {
    // Absorb 2, squeeze 1,  domainsep = 0x4142
    // [0x80000002, 0x00000001, 0x4142]
    const T1_DS: u128 = 0x80000002000000014142;
    const COEFF_DS: &[u8] = b"KeyGenPolyCoeff";

    pub fn coeffs(&self) -> &[ScalarField] {
        &self.poly
    }

    // Returns the used domain separator as a field element for the encryption
    fn get_t1_ds() -> BaseField {
        BaseField::from(Self::T1_DS)
    }

    // Returns the used domain separator as a field element for the commitment to the coefficients
    fn get_coeff_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::COEFF_DS)
    }

    fn interpret_scalarfield_as_basefield(s: ScalarField) -> BaseField {
        let s_bigint = s.into_bigint();
        BaseField::from_bigint(s_bigint).expect("scalar field element fits in base field")
    }

    fn basefield_as_scalarfield_if_fits(s: BaseField) -> std::io::Result<ScalarField> {
        let s_bigint = s.into_bigint();
        ScalarField::from_bigint(s_bigint).ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "base field element does not fit in scalar field",
        ))
    }

    fn commit_poly(poly: &[ScalarField]) -> (Affine, BaseField) {
        let comm_share = Affine::generator() * poly[0];

        // Sponge mode for hashing
        let poseidon2_4 = Poseidon2::<BaseField, 4, 5>::default();
        let mut state = [BaseField::zero(); 4];
        state[0] = Self::get_coeff_ds(); // domain separator in capacity
        for coeffs_ in poly[1..].chunks(3) {
            for (s, c) in izip!(state.iter_mut().skip(1), coeffs_) {
                *s += Self::interpret_scalarfield_as_basefield(*c);
            }
            poseidon2_4.permutation_in_place(&mut state);
        }
        let comm_coeffs = state[1];
        (comm_share.into_affine(), comm_coeffs)
    }

    pub fn keygen<R: Rng + CryptoRng>(rng: &mut R, degree: usize) -> Self {
        let poly = (0..degree + 1)
            .map(|_| ScalarField::rand(rng))
            .collect::<Vec<_>>();

        let (comm_share, comm_coeffs) = Self::commit_poly(&poly);

        Self {
            poly,
            comm_share,
            comm_coeffs,
        }
    }

    pub fn reshare<R: Rng + CryptoRng>(rng: &mut R, my_share: ScalarField, degree: usize) -> Self {
        let mut poly = Vec::with_capacity(degree + 1);
        poly.push(my_share);
        for _ in 0..degree {
            poly.push(ScalarField::rand(rng));
        }

        let (comm_share, comm_coeffs) = Self::commit_poly(&poly);

        Self {
            poly,
            comm_share,
            comm_coeffs,
        }
    }

    fn dh_key_derivation(my_sk: &ScalarField, their_pk: Affine) -> BaseField {
        (their_pk * my_sk).into_affine().x
    }

    fn sym_encrypt(key: BaseField, msg: ScalarField, nonce: BaseField) -> BaseField {
        let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
        let ks = poseidon2_3.permutation(&[Self::get_t1_ds(), key, nonce]);
        ks[1] + Self::interpret_scalarfield_as_basefield(msg)
    }

    fn sym_decrypt(
        key: BaseField,
        ciphertext: BaseField,
        nonce: BaseField,
    ) -> std::io::Result<ScalarField> {
        let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
        let ks = poseidon2_3.permutation(&[Self::get_t1_ds(), key, nonce]);
        let msg = ciphertext - ks[1];
        Self::basefield_as_scalarfield_if_fits(msg)
    }

    pub fn decrypt_share(
        my_sk: &ScalarField,
        their_pk: Affine,
        ciphertext: BaseField,
        nonce: BaseField,
    ) -> std::io::Result<ScalarField> {
        let symm_key = Self::dh_key_derivation(my_sk, their_pk);
        Self::sym_decrypt(symm_key, ciphertext, nonce)
    }

    // Party ID from 0..n-1
    // Returns the commitment to the share and the encrypted share
    pub fn gen_share(
        &self,
        id: usize,
        my_sk: &ScalarField,
        their_pk: Affine,
        nonce: BaseField,
    ) -> (Affine, BaseField) {
        let index = ScalarField::from((id + 1) as u64);
        let share = shamir::evaluate_poly(&self.poly, index);

        let symm_key = Self::dh_key_derivation(my_sk, their_pk);
        let ciphertext = Self::sym_encrypt(symm_key, share, nonce);

        // The share is random, so no need for randomness here
        let commitment = Affine::generator() * share;

        (commitment.into_affine(), ciphertext)
    }

    pub fn accumulate_shares(shares: &[ScalarField]) -> ScalarField {
        shares.iter().fold(ScalarField::zero(), |acc, x| acc + x)
    }

    pub fn accumulate_pks(pks: &[Affine]) -> Affine {
        pks.iter()
            .fold(ark_babyjubjub::EdwardsProjective::zero(), |acc, x| acc + *x)
            .into_affine()
    }

    // Returns the first lagrange coefficients for the given degree
    pub fn lagrange_coeffs(degree: usize) -> Vec<ScalarField> {
        let indices: Vec<usize> = (1..=degree + 1).collect();
        shamir::lagrange_from_coeff(&indices)
    }

    // Only the first lagrange.len() shares are used
    pub fn accumulate_lagrange_shares(
        shares: &[ScalarField],
        lagrange: &[ScalarField],
    ) -> ScalarField {
        assert!(shares.len() >= lagrange.len());
        let shares = &shares[0..lagrange.len()];
        let mut result = ScalarField::zero();
        for (share, l) in izip!(shares.iter(), lagrange.iter()) {
            result += *share * *l;
        }
        result
    }

    // Only the first lagrange.len() public keys are used
    pub fn accumulate_lagrange_pks(pks: &[Affine], lagrange: &[ScalarField]) -> Affine {
        assert!(pks.len() >= lagrange.len());
        let pks = &pks[0..lagrange.len()];
        Projective::msm_unchecked(pks, lagrange).into_affine()
    }

    pub fn degree(&self) -> usize {
        self.poly.len() - 1
    }

    pub fn get_pk_share(&self) -> Affine {
        self.comm_share
    }

    pub fn get_coeff_commitment(&self) -> BaseField {
        self.comm_coeffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_distributed_keygen(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        // Init party secret keys and public keys
        let party_sks = (0..num_parties)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let party_pks = party_sks
            .iter()
            .map(|x| (Affine::generator() * *x).into_affine())
            .collect::<Vec<_>>();

        // 1. Each party commits to a random polynomial
        let party_polys = (0..num_parties)
            .map(|_| KeyGenPoly::keygen(&mut rng, degree))
            .collect::<Vec<_>>();

        // The desired result based on the created polys
        let should_sk = party_polys
            .iter()
            .fold(ScalarField::zero(), |acc, x| acc + x.poly[0]);
        let should_pk = Affine::generator() * should_sk;

        // pk from commitments
        let pks = party_polys
            .iter()
            .map(|x| x.get_pk_share())
            .collect::<Vec<_>>();
        let pk_from_comm = KeyGenPoly::accumulate_pks(&pks);
        assert_eq!(should_pk, pk_from_comm);

        // 2. Each party creates all shares
        let mut encryption_nonces = Vec::with_capacity(num_parties);
        let mut party_ciphers = Vec::with_capacity(num_parties);
        for (poly, my_sk) in izip!(party_polys, party_sks.iter()) {
            let mut nonces = Vec::with_capacity(num_parties);
            let mut cipher = Vec::with_capacity(num_parties);
            for (i, their_pk) in party_pks.iter().enumerate() {
                let nonce = BaseField::rand(&mut rng);
                let (_, ciphertext) = poly.gen_share(i, my_sk, *their_pk, nonce);
                nonces.push(nonce);
                cipher.push(ciphertext);
            }
            encryption_nonces.push(nonces);
            party_ciphers.push(cipher);
        }

        // 3. Each party decrypts their shares
        let mut result_shares = Vec::with_capacity(num_parties);
        for (i, my_sk) in party_sks.iter().enumerate() {
            let mut my_shares = Vec::with_capacity(num_parties);
            for (cipher, nonce, their_pk) in izip!(
                party_ciphers.iter(),
                encryption_nonces.iter(),
                party_pks.iter()
            ) {
                let share = KeyGenPoly::decrypt_share(my_sk, *their_pk, cipher[i], nonce[i])
                    .expect("decryption should work");
                my_shares.push(share);
            }
            let my_share = KeyGenPoly::accumulate_shares(&my_shares);
            result_shares.push(my_share);
        }

        // Check if the correct secret share is obtained
        let sk_from_shares = shamir::reconstruct_random_shares(&result_shares, degree, &mut rng);
        assert_eq!(should_sk, sk_from_shares);

        // Check if the correct public key is obtained
        let pk_shares = result_shares
            .iter()
            .map(|x| Affine::generator() * *x)
            .collect::<Vec<_>>();
        let pk_from_shares = shamir::reconstruct_random_pointshares(&pk_shares, degree, &mut rng);
        assert_eq!(should_pk, pk_from_shares);
    }

    #[test]
    fn test_distributed_keygen_3_1() {
        test_distributed_keygen(3, 1);
    }

    #[test]
    fn test_distributed_keygen_31_15() {
        test_distributed_keygen(31, 15);
    }

    fn test_reshare(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        // Init party secret keys and public keys
        let party_sks = (0..num_parties)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let party_pks = party_sks
            .iter()
            .map(|x| (Affine::generator() * *x).into_affine())
            .collect::<Vec<_>>();

        ///////////////////////////////////////////////////
        // PHASE 1: Initial key generation

        // 1. Each party commits to a random polynomial
        let party_polys = (0..num_parties)
            .map(|_| KeyGenPoly::keygen(&mut rng, degree))
            .collect::<Vec<_>>();

        // The desired result based on the created polys
        let should_sk = party_polys
            .iter()
            .fold(ScalarField::zero(), |acc, x| acc + x.poly[0]);
        let should_pk = Affine::generator() * should_sk;

        // pk from commitments
        let pks = party_polys
            .iter()
            .map(|x| x.get_pk_share())
            .collect::<Vec<_>>();
        let pk_from_comm = KeyGenPoly::accumulate_pks(&pks);
        assert_eq!(should_pk, pk_from_comm);

        // 2. Each party creates all shares
        let mut encryption_nonces = Vec::with_capacity(num_parties);
        let mut party_ciphers = Vec::with_capacity(num_parties);
        let mut party_commitments = Vec::with_capacity(num_parties);
        for (poly, my_sk) in izip!(party_polys, party_sks.iter()) {
            let mut nonces = Vec::with_capacity(num_parties);
            let mut cipher = Vec::with_capacity(num_parties);
            let mut commitments = Vec::with_capacity(num_parties);
            for (i, their_pk) in party_pks.iter().enumerate() {
                let nonce = BaseField::rand(&mut rng);
                let (comm, ciphertext) = poly.gen_share(i, my_sk, *their_pk, nonce);
                nonces.push(nonce);
                cipher.push(ciphertext);
                commitments.push(comm);
            }
            encryption_nonces.push(nonces);
            party_ciphers.push(cipher);
            party_commitments.push(commitments);
        }

        // 3. Each party decrypts their shares
        let mut result_shares = Vec::with_capacity(num_parties);
        for (i, my_sk) in party_sks.iter().enumerate() {
            let mut my_shares = Vec::with_capacity(num_parties);
            for (cipher, nonce, their_pk) in izip!(
                party_ciphers.iter(),
                encryption_nonces.iter(),
                party_pks.iter()
            ) {
                let share = KeyGenPoly::decrypt_share(my_sk, *their_pk, cipher[i], nonce[i])
                    .expect("decryption should work");
                my_shares.push(share);
            }
            let my_share = KeyGenPoly::accumulate_shares(&my_shares);
            result_shares.push(my_share);
        }

        // Check if the correct secret share is obtained
        let sk_from_shares = shamir::reconstruct_random_shares(&result_shares, degree, &mut rng);
        assert_eq!(should_sk, sk_from_shares);

        // Check if the correct public key is obtained
        let pk_shares = result_shares
            .iter()
            .map(|x| Affine::generator() * *x)
            .collect::<Vec<_>>();
        let pk_from_shares = shamir::reconstruct_random_pointshares(&pk_shares, degree, &mut rng);
        assert_eq!(should_pk, pk_from_shares);

        ///////////////////////////////////////////////////
        // PHASE 2: Reshare

        // Lagrange coefficients for the first degree+1 parties
        let lagrange = KeyGenPoly::lagrange_coeffs(degree);

        // 1. First degree + 1 parties commit to a random polynomial
        let party_polys = result_shares
            .into_iter()
            .take(degree + 1)
            .map(|share| KeyGenPoly::reshare(&mut rng, share, degree))
            .collect::<Vec<_>>();

        // pk from commitments
        let pks = party_polys
            .iter()
            .map(|x| x.get_pk_share())
            .collect::<Vec<_>>();
        let pk_from_comm = KeyGenPoly::accumulate_lagrange_pks(&pks, &lagrange);
        assert_eq!(should_pk, pk_from_comm);

        // 2. First degree + 1 parties create all shares
        let mut encryption_nonces = Vec::with_capacity(degree + 1);
        let mut party_ciphers = Vec::with_capacity(degree + 1);
        for (poly, my_sk) in izip!(party_polys.iter(), party_sks.iter()) {
            let mut nonces = Vec::with_capacity(num_parties);
            let mut cipher = Vec::with_capacity(num_parties);
            for (i, their_pk) in party_pks.iter().enumerate() {
                let nonce = BaseField::rand(&mut rng);
                let (_, ciphertext) = poly.gen_share(i, my_sk, *their_pk, nonce);
                nonces.push(nonce);
                cipher.push(ciphertext);
            }
            encryption_nonces.push(nonces);
            party_ciphers.push(cipher);
        }

        // 3. Each party decrypts their shares
        let mut result_shares = Vec::with_capacity(num_parties);
        for (i, my_sk) in party_sks.iter().enumerate() {
            let mut my_shares = Vec::with_capacity(degree + 1);
            for (cipher, nonce, their_pk) in izip!(
                party_ciphers.iter(),
                encryption_nonces.iter(),
                party_pks.iter()
            ) {
                let share = KeyGenPoly::decrypt_share(my_sk, *their_pk, cipher[i], nonce[i])
                    .expect("decryption should work");
                my_shares.push(share);
            }
            let my_share = KeyGenPoly::accumulate_lagrange_shares(&my_shares, &lagrange);
            result_shares.push(my_share);
        }

        // Check if the correct secret share is obtained
        let sk_from_shares = shamir::reconstruct_random_shares(&result_shares, degree, &mut rng);
        assert_eq!(should_sk, sk_from_shares);

        // Check if the correct public key is obtained
        let pk_shares = result_shares
            .iter()
            .map(|x| Affine::generator() * *x)
            .collect::<Vec<_>>();
        let pk_from_shares = shamir::reconstruct_random_pointshares(&pk_shares, degree, &mut rng);
        assert_eq!(should_pk, pk_from_shares);

        // Check that the correct share was used in the polynomial
        // This can be checked outside of the ZK proof (e.g., in the SC) using the commitments
        for (i, poly) in party_polys.iter().enumerate() {
            let mut reconstructed_commitment = Affine::zero();
            for comm in party_commitments.iter() {
                // For later reshares, the following sum needs to be replaced by a weighted sum using the lagrange coefficients
                reconstructed_commitment = (reconstructed_commitment + comm[i]).into_affine();
            }
            assert_eq!(poly.get_pk_share(), reconstructed_commitment);
        }
    }

    #[test]
    fn test_reshare_3_1() {
        test_reshare(3, 1);
    }

    #[test]
    fn test_reshare_31_15() {
        test_reshare(31, 15);
    }
}
