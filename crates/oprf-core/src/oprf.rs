use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use crate::dlog_equality::DLogEqualityProof;

type Curve = ark_babyjubjub::EdwardsProjective;
type ScalarField = <Curve as PrimeGroup>::ScalarField;
type BaseField = <Curve as CurveGroup>::BaseField;
type Affine = <Curve as CurveGroup>::Affine;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OPrfError {
    #[error(
        "Request ID mismatch: The provided blinding factor does not match the request ID in the response."
    )]
    RequestIdMismatch,
    #[error("Invalid proof: The provided DLOG equality proof is invalid.")]
    InvalidProof,
}

#[derive(ZeroizeOnDrop)]
pub struct OPrfKey {
    /// secret scalar for the OPRF
    key: ScalarField,
}

impl OPrfKey {
    pub fn new(key: ScalarField) -> Self {
        OPrfKey { key }
    }

    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let key = ScalarField::rand(rng);
        OPrfKey { key }
    }

    pub fn public_key(&self) -> Curve {
        Curve::generator() * self.key
    }
}

pub struct OPrfService {
    /// the OPrf key used for the service
    key: OPrfKey,
    /// the public key derived from the OPrf key, cached for convenience
    public_key: Affine,
}

impl OPrfService {
    pub fn new(key: OPrfKey) -> Self {
        let public_key = key.public_key().into_affine();
        OPrfService { key, public_key }
    }

    pub fn key(&self) -> &OPrfKey {
        &self.key
    }

    pub fn public_key(&self) -> &Affine {
        &self.public_key
    }

    pub fn answer_query(&self, query: BlindedOPrfRequest) -> BlindedOPrfResponse {
        // Compute the blinded response
        let blinded_response = (query.blinded_query * self.key.key).into_affine();
        BlindedOPrfResponse {
            request_id: query.request_id,
            blinded_response,
        }
    }
    pub fn answer_query_with_proof(
        &self,
        query: BlindedOPrfRequest,
    ) -> (BlindedOPrfResponse, DLogEqualityProof) {
        // Compute the blinded response
        let blinded_response = (query.blinded_query * self.key.key).into_affine();

        let proof =
            DLogEqualityProof::proof(query.blinded_query, self.key.key, &mut rand::thread_rng());
        (
            BlindedOPrfResponse {
                request_id: query.request_id,
                blinded_response,
            },
            proof,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOPrfRequest {
    /// request id
    pub(crate) request_id: Uuid,
    /// the blinded query
    pub(crate) blinded_query: Affine,
}

impl BlindedOPrfRequest {
    pub fn blinded_query_as_public_output(&self) -> [BaseField; 2] {
        [self.blinded_query.x, self.blinded_query.y]
    }

    pub fn blinded_query(&self) -> Affine {
        self.blinded_query
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindingFactor {
    /// the blinding factor used to blind the query
    pub factor: ScalarField,
    /// original query
    pub query: BaseField,
    // request id, to track the response to the request
    pub request_id: Uuid,
}

impl BlindingFactor {
    pub fn prepare(self) -> PreparedBlindingFactor {
        PreparedBlindingFactor {
            factor: self
                .factor
                .inverse()
                .expect("Blinding factor should not be zero"),
            request_id: self.request_id,
            query: self.query,
        }
    }

    pub fn beta(&self) -> ScalarField {
        self.factor
    }

    pub fn query(&self) -> BaseField {
        self.query
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBlindingFactor {
    /// the inverse of the blinding factor used to blind the query
    pub factor: ScalarField,
    /// original query
    query: BaseField,
    // request id, to track the response to the request
    request_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOPrfResponse {
    /// request id, to track the response to the request
    pub request_id: Uuid,
    /// the blinded response
    pub blinded_response: Affine,
}

pub struct OprfClient {
    /// the public key of the OPrf service
    public_key: Affine,
}

impl OprfClient {
    const OPRF_DS: &[u8] = b"World ID Proof";
    const QUERY_DS: &[u8] = b"World ID Query";
    const ID_COMMITMENT_DS: &[u8] = b"H(id, r)";

    pub fn new(public_key: Affine) -> Self {
        OprfClient { public_key }
    }

    // Returns the domain separator for the query finalization as a field element
    fn get_oprf_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::OPRF_DS)
    }

    // Returns the domain separator for the query generation as a field element
    fn get_query_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::QUERY_DS)
    }

    // Returns the domain separator for the id commitment as a field element
    fn get_id_commitment_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::ID_COMMITMENT_DS)
    }

    pub fn id_commitment(index: BaseField, r: BaseField) -> BaseField {
        let poseidon = Poseidon2::<_, 3, 5>::default();
        // capacity of the sponge has domain separator
        let input = [Self::get_id_commitment_ds(), index, r];
        poseidon.permutation(&input)[1]
    }

    /// Generates the query field element from the index, rp_id, and action.
    pub fn generate_query(index: BaseField, rp_id: BaseField, action: BaseField) -> BaseField {
        let poseidon = Poseidon2::<_, 4, 5>::default();
        // capacity of the sponge has domain separator
        let input = [Self::get_query_ds(), index, rp_id, action];
        poseidon.permutation(&input)[1]
    }

    /// Blinds a query for the OPRF service, generating a blinding factor and a request ID.
    /// The provided query field element is mapped to a point on the curve, using Elligator2 based methods.
    pub fn blind_query<R: Rng + CryptoRng>(
        &self,
        request_id: Uuid,
        query: BaseField,
        rng: &mut R,
    ) -> (BlindedOPrfRequest, BlindingFactor) {
        // Generate a random blinding factor and request ID
        let blinding_factor = loop {
            let random = ScalarField::rand(rng);
            if !random.is_zero() {
                break random;
            }
        };
        let encoded_input = mappings::encode_to_curve(query);
        let blinded_query = (encoded_input * blinding_factor).into_affine();
        (
            BlindedOPrfRequest {
                request_id,
                blinded_query,
            },
            BlindingFactor {
                factor: blinding_factor,
                query,
                request_id,
            },
        )
    }

    pub fn finalize_query(
        &self,
        response: BlindedOPrfResponse,
        blinding_factor: PreparedBlindingFactor,
    ) -> Result<BaseField, OPrfError> {
        // Unblind the response using the blinding factor
        if response.request_id != blinding_factor.request_id {
            return Err(OPrfError::RequestIdMismatch);
        }
        let unblinded_response = response.blinded_response * blinding_factor.factor;
        let unblinded_point = unblinded_response.into_affine();

        // compute the second hash in the 2Hash-DH construction
        // out = H(query, unblinded_point)
        let hash_input = [
            Self::get_oprf_ds(), // capacity of the sponge with domain separator
            blinding_factor.query,
            unblinded_point.x,
            unblinded_point.y,
        ];

        let poseidon = Poseidon2::<_, 4, 5>::default();
        let output = poseidon.permutation(&hash_input);
        Ok(output[1]) // Return the first element of the state as the field element,
    }

    pub fn finalize_query_and_verify_proof(
        &self,
        response: BlindedOPrfResponse,
        proof: DLogEqualityProof,
        blinding_factor: PreparedBlindingFactor,
    ) -> Result<BaseField, OPrfError> {
        // Verify the proof
        let d = Curve::generator().into_affine();
        let a = self.public_key;
        //TODO: save this element to avoid recomputing it?
        let b = (mappings::encode_to_curve(blinding_factor.query)
            * blinding_factor.factor.inverse().unwrap())
        .into_affine();
        let c = response.blinded_response;

        if !proof.verify(a, b, c, d) {
            return Err(OPrfError::InvalidProof);
        }
        // Call finalize_query to unblind the response
        self.finalize_query(response, blinding_factor)
    }
}

mod mappings {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInt, BigInteger, Field, One, PrimeField, Zero};
    use poseidon2::Poseidon2;
    use subtle::{Choice, ConstantTimeEq};

    use crate::oprf::{Affine, BaseField};

    fn ct_eq<F: PrimeField>(lhs: F, rhs: F) -> Choice {
        // Ideally the ark ecosystem would support subtle, so this is currently
        // the best thing we can do. Serialize the elements and then compare the
        // byte representation.
        let mut lhs_v = Vec::with_capacity(lhs.uncompressed_size());
        let mut rhs_v = Vec::with_capacity(rhs.uncompressed_size());
        lhs.serialize_uncompressed(&mut lhs_v).unwrap();
        rhs.serialize_uncompressed(&mut rhs_v).unwrap();
        lhs_v.ct_eq(&rhs_v)
    }

    fn ct_is_zero<F: PrimeField>(v: F) -> Choice {
        // Ideally the ark ecosystem would support subtle, so this is currently
        // the best thing we can do. Serialize the elements and then compare the
        // byte representation.
        let mut lhs_v = Vec::with_capacity(v.uncompressed_size());
        let rhs_v = vec![0; v.uncompressed_size()];
        v.serialize_uncompressed(&mut lhs_v).unwrap();
        lhs_v.ct_eq(&rhs_v)
    }

    fn ct_select<F: PrimeField>(lhs: F, rhs: F, choice: Choice) -> F {
        // Ideally the ark ecosystem would support subtle.
        let choice = F::from(choice.unwrap_u8());
        rhs + (lhs - rhs) * choice
    }

    fn ct_is_square<F: PrimeField>(x: F) -> Choice {
        let x = x.pow(F::MODULUS_MINUS_ONE_DIV_TWO);
        // TODO this ct_eq and ct_is_zero could be folded into one serialization operation and then comparison
        let c1 = ct_eq(x, F::ONE);
        let c2 = ct_is_zero(x);
        c1 ^ c2
    }

    /// A curve encoding function that maps a field element to a point on the curve, based on [RFC9380, Section 3](https://www.rfc-editor.org/rfc/rfc9380.html#name-encoding-byte-strings-to-el).
    ///
    /// As mentioned in the RFC, this encoding is non uniformly random in E, as this can only hit about half of the of the curve points.
    pub fn encode_to_curve(input: BaseField) -> Affine {
        // Map the input to a point on the curve using Elligator2
        let u = hash_to_field(input);
        let q = map_to_curve_twisted_edwards(u);
        q.clear_cofactor()
    }

    /// A curve encoding function that maps a field element to a point on the curve, based on [RFC9380, Section 3](https://www.rfc-editor.org/rfc/rfc9380.html#name-encoding-byte-strings-to-el).
    ///
    /// In contrast to `encode_to_curve`, this function uses a two-step mapping to ensure that the output is uniformly random over the curve.
    #[allow(dead_code)]
    pub fn hash_to_curve(input: BaseField) -> Affine {
        // Map the input to a point on the curve using Elligator2
        let [u0, u1] = hash_to_field2(input);
        let q0 = map_to_curve_twisted_edwards(u0);
        let q1 = map_to_curve_twisted_edwards(u1);
        let r = (q0 + q1).into_affine();
        r.clear_cofactor()
    }

    /// An implementation of `hash_to_field` based on [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    /// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
    fn hash_to_field(input: BaseField) -> BaseField {
        // hash the input to a field element using poseidon hash
        let poseidon: Poseidon2<
            ark_ff::Fp<ark_ff::MontBackend<ark_babyjubjub::FqConfig, 4>, 4>,
            3,
            5,
        > = Poseidon2::<_, 3, 5>::default();
        let output = poseidon.permutation(&[BaseField::zero(), input, BaseField::zero()]);
        output[1] // Return the first element of the state as the field element, element 0 is the capacity of the sponge
    }

    /// An implementation of `hash_to_field` based on [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    /// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
    fn hash_to_field2(input: BaseField) -> [BaseField; 2] {
        // hash the input to a field element using poseidon hash
        let poseidon = Poseidon2::<_, 3, 5>::default();
        let output = poseidon.permutation(&[BaseField::zero(), input, BaseField::zero()]);

        [output[1], output[2]] // Return the first two elements of the state as the field elements, element 0 is the capacity of the sponge
    }

    /// Maps the input to a point on the curve, without anyone knowing the DLOG of the curve point.
    ///
    /// This is based on `map_to_curve` from [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    /// We use section 6.8 ("Mappings for Twisted Edwards Curves") to map the input to a point on the curve.
    /// This internally uses a birationally equivalent Montgomery curve to perform the mapping, then uses a rational map to convert the point to the Edwards curve.
    fn map_to_curve_twisted_edwards(input: BaseField) -> Affine {
        let (s, t) = map_to_curve_elligator2(input);
        let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
        Affine { x: v, y: w }
    }

    /// Maps the input to a point on the Montgomery curve, without anyone knowing the DLOG of the curve point.
    ///
    /// Returns the s and t coordinates of the point on the Montgomery curve.
    ///
    /// let the Montgomery curve be defined by the equation $K*t^2 = s^3 + J*s^2 + s$.
    /// We follow the Elligator2 mapping as described in [RFC9380, Section 6.7.1](https://www.rfc-editor.org/rfc/rfc9380.html#name-elligator-2-method).
    fn map_to_curve_elligator2(input: BaseField) -> (BaseField, BaseField) {
        // constant c1 = J/K;
        let j = BaseField::from(168698);
        // since k = 1 for Baby JubJub, this simplifies a few operations below
        let c1 = j;
        // The constant c2 would be 1/(k*k) = 1, so we also skip it
        // constant Z = 5, based on RFC9380, Appendix H.3.
        // ```sage
        // # Argument:
        // # - F, a field object, e.g., F = GF(2^255 - 19)
        // def find_z_ell2(F):
        //     ctr = F.gen()
        //     while True:
        //         for Z_cand in (F(ctr), F(-ctr)):
        //             # Z must be a non-square in F.
        //             if is_square(Z_cand):
        //                 continue
        //             return Z_cand
        //         ctr += 1
        // # BaseField of Baby JubJub curve:
        // F = GF(21888242871839275222246405745257275088548364400416034343698204186575808495617)
        // find_z_ell2(F) # 5
        // ```
        let z = BaseField::from(5);
        let tv1 = input * input;
        let tv1 = z * tv1;
        let e = ct_is_zero(tv1 + BaseField::ONE);
        let tv1 = ct_select(BaseField::zero(), tv1, e);
        let x1 = tv1 + BaseField::one();
        let x1 = inv0(x1);
        let x1 = -c1 * x1;
        let gx1 = x1 + c1;
        // normally the calculation of gx1 below would involve c2, but since c2 = 1 for Baby JubJub, we can simplify it
        let gx1 = gx1 * x1.square() + x1;
        let x2 = -x1 - c1;
        let gx2 = tv1 * gx1;
        let e2 = ct_is_square(gx1);
        let (x, y2) = (ct_select(x1, x2, e2), ct_select(gx1, gx2, e2));
        let y = y2
            .sqrt()
            .expect("y2 should be a square based on our conditional selection above");
        let e3 = Choice::from(sgn0(y) as u8);
        let y = ct_select(-y, y, e2 ^ e3);
        // the reduced (s,t) would normally be (x*k,y*k), but since k = 1 for Baby JubJub, we can skip that step
        (x, y)
    }

    /// Converts a point from Montgomery to Twisted Edwards using the rational map.
    ///
    /// This is based on appendix D1 of [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    ///
    /// Let the twisted Edwards curve be defined by the equation $a*v^2 + w^2 = 1 + d*v^2*w^2$.
    /// let the Montgomery curve be defined by the equation $K*t^2 = s^3 + J*s^2 + s$, with
    /// $J = 2 * (a + d) / (a - d)$ and $K = 4 / (a - d)$.
    ///
    /// For the concrete case of Baby JubJub, we have:
    /// - $K = 1$
    /// - $J = 168698$
    /// - $a = 168700$
    /// - $d = 168696$
    ///
    /// Input: (s, t), a point on the curve $K * t^2 = s^3 + J * s^2 + s$.
    /// Output: (v, w), a point on the equivalent twisted Edwards curve.
    /// (This function also handles exceptional cases where the point is at infinity correctly.)
    fn rational_map_mont_to_twisted_edwards(s: BaseField, t: BaseField) -> (BaseField, BaseField) {
        // Convert the point from Montgomery to Twisted Edwards using the rational map
        let tv1 = s + BaseField::one();
        let tv2 = tv1 * t;
        let tv2 = inv0(tv2);
        let v = tv1 * tv2;
        let v = v * s;
        let w = tv2 * t;
        let tv1 = s - BaseField::one();
        let w = w * tv1;
        let e = ct_is_zero(tv2);
        let w = ct_select(BaseField::one(), w, e);
        (v, w)
    }

    trait Inv0Constants: PrimeField {
        const MODULUS_MINUS_2: Self::BigInt;
    }

    impl Inv0Constants for BaseField {
        const MODULUS_MINUS_2: Self::BigInt = BigInt!(
            "21888242871839275222246405745257275088548364400416034343698204186575808495615"
        );
    }

    /// Computes the inverse of a field element, returning zero if the element is zero.
    fn inv0<F: PrimeField + Inv0Constants>(x: F) -> F {
        x.pow(F::MODULUS_MINUS_2)
    }

    /// Computes the `sgn0` function for a field element, based on the definition in [RFC9380, Section 4.1](https://www.rfc-editor.org/rfc/rfc9380.html#name-the-sgn0-function).
    fn sgn0<F: PrimeField>(x: F) -> bool {
        x.into_bigint().is_odd()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ark_ff::UniformRand;
        use std::str::FromStr;

        #[test]
        fn test_map_to_curve_twisted_edwards() {
            let input = BaseField::from(42);
            let (s, t) = map_to_curve_elligator2(input);
            let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
            let point = Affine { x: v, y: w };
            assert!(point.is_on_curve());
        }
        #[test]
        fn test_map_to_curve_twisted_edwards_rand() {
            for _ in 0..100 {
                // Test with random inputs
                let input = BaseField::rand(&mut rand::thread_rng());
                let (s, t) = map_to_curve_elligator2(input);
                let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
                let point = Affine { x: v, y: w };
                assert!(point.is_on_curve(), "Failed for input: {:?}", input);
            }
        }

        #[test]
        fn test_encode_to_curve() {
            let input = BaseField::from(42);
            let point = encode_to_curve(input);
            assert!(point.is_on_curve());

            let expected_point = Affine {
                x: BaseField::from_str(
                    "2248614069508207507326262781062587749986544721157984531256611865469864958775",
                )
                .unwrap(),
                y: BaseField::from_str(
                    "11346329236507494865585709204927959305406795872019529850625216399990666158973",
                )
                .unwrap(),
            };
            assert_eq!(expected_point, point);
        }
        #[test]
        fn test_hash_to_curve() {
            let input = BaseField::from(42);
            let point = hash_to_curve(input);
            assert!(point.is_on_curve());
        }

        #[test]
        fn test_ct_is_zero() {
            assert_eq!(ct_is_zero(BaseField::zero()).unwrap_u8(), 1);
        }

        #[test]
        fn test_inv0() {
            for _ in 0..100 {
                let input = BaseField::rand(&mut rand::thread_rng());
                let output = inv0(input);
                assert_eq!(
                    input * output,
                    if !input.is_zero() {
                        BaseField::ONE
                    } else {
                        BaseField::zero()
                    }
                );
            }

            assert_eq!(inv0(BaseField::zero()), BaseField::zero());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_determinism() {
        let mut rng = rand::thread_rng();
        let request_id = Uuid::new_v4();
        let request_id2 = Uuid::new_v4();
        let key = OPrfKey::random(&mut rng);
        let service = OPrfService::new(key);
        let client = OprfClient::new(*service.public_key());

        let query =
            OprfClient::generate_query(BaseField::from(42), BaseField::from(2), BaseField::from(3));
        let (blinded_request, blinding_factor) = client.blind_query(request_id, query, &mut rng);
        let (blinded_request2, blinding_factor2) = client.blind_query(request_id2, query, &mut rng);
        assert_ne!(blinded_request, blinded_request2);
        assert_ne!(
            blinded_request.blinded_query,
            blinded_request2.blinded_query
        );
        let response = service.answer_query(blinded_request);

        let response = client
            .finalize_query(response, blinding_factor.prepare())
            .unwrap();

        let expected_response = (mappings::encode_to_curve(query) * service.key.key).into_affine();
        let poseidon = Poseidon2::<_, 4, 5>::default();
        let out = poseidon.permutation(&[
            OprfClient::get_oprf_ds(),
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(response, expected_output);
        let response2 = service.answer_query(blinded_request2);

        let unblinded_response2 = client
            .finalize_query(response2, blinding_factor2.prepare())
            .unwrap();
        assert_eq!(response, unblinded_response2);
    }

    #[test]
    fn test_oprf_with_proof() {
        let mut rng = rand::thread_rng();
        let request_id = Uuid::new_v4();
        let request_id2 = Uuid::new_v4();
        let key = OPrfKey::random(&mut rng);
        let service = OPrfService::new(key);
        let client = OprfClient::new(*service.public_key());

        let query =
            OprfClient::generate_query(BaseField::from(42), BaseField::from(2), BaseField::from(3));
        let (blinded_request, blinding_factor) = client.blind_query(request_id, query, &mut rng);
        let (blinded_request2, blinding_factor2) = client.blind_query(request_id2, query, &mut rng);
        assert_ne!(blinded_request, blinded_request2);
        assert_ne!(
            blinded_request.blinded_query,
            blinded_request2.blinded_query
        );
        let (response, proof) = service.answer_query_with_proof(blinded_request);

        let unblinded_response = client
            .finalize_query_and_verify_proof(
                response.clone(),
                proof,
                blinding_factor.clone().prepare(),
            )
            .unwrap();

        let expected_response = (mappings::encode_to_curve(query) * service.key.key).into_affine();
        let poseidon = Poseidon2::<_, 4, 5>::default();
        let out = poseidon.permutation(&[
            OprfClient::get_oprf_ds(),
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(unblinded_response, expected_output);

        let (response2, proof2) = service.answer_query_with_proof(blinded_request2);
        let unblinded_response2 = client
            .finalize_query_and_verify_proof(response2, proof2.clone(), blinding_factor2.prepare())
            .unwrap();
        assert_eq!(unblinded_response, unblinded_response2);

        assert_eq!(
            client.finalize_query_and_verify_proof(response, proof2, blinding_factor.prepare()),
            Err(OPrfError::InvalidProof)
        );
    }
}
