//! WIP-106: proving an Authenticator Attestation with ProveKit, via the
//! `attestation-proof` reference circuit.

use std::{collections::BTreeMap, io::Read};

use ark_ff::{BigInteger as _, PrimeField as _};
use provekit_common::{InputMap, InputValue, NoirElement, NoirProof};
use provekit_prover::Prove as _;
use provekit_verifier::Verify as _;

use crate::{
    NoirCircuitInput, NoirRepresentable as _, ProofError,
    authenticator_attestation::assertion_key_coordinates,
    circuit_inputs::AttestationProofCircuitInput, errors::ProofInputError,
};

/// Maximum remaining AAT validity in seconds; mirrors `MAX_AAT_LIFETIME_SECS` in `aat.nr`.
pub const MAX_AAT_LIFETIME_SECS: u32 = 1800;

/// Maximum remaining TAKT validity in seconds; mirrors `MAX_TAKT_LIFETIME_SECS` in `takt.nr`.
pub const MAX_TAKT_LIFETIME_SECS: u32 = 604_800;

/// Loads an attestation proof prover from PKP bytes.
///
/// # Errors
/// Fails if the bytes cannot be read or deserialized.
pub fn load_attestation_prover_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads an attestation proof verifier from PKV bytes.
///
/// # Errors
/// Fails if the bytes cannot be read or deserialized.
pub fn load_attestation_verifier_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Checks one token's freshness the way the circuit does.
fn check_token_freshness(
    token: &'static str,
    exp: u32,
    now: u32,
    max_lifetime_secs: u32,
) -> Result<(), ProofInputError> {
    if u16::try_from(exp).is_ok() {
        return Err(ProofInputError::TokenExpirationOutOfRange { token, exp });
    }
    if now >= exp {
        return Err(ProofInputError::TokenExpired { token, exp, now });
    }
    if exp - now > max_lifetime_secs {
        return Err(ProofInputError::TokenLifetimeExceeded {
            token,
            exp,
            now,
            max_lifetime_secs,
        });
    }
    Ok(())
}

/// Emulates the circuit's freshness constraints so caller mistakes surface as
/// specific errors instead of opaque proving failures; the claim bindings hold
/// by construction since the public inputs are derived from the token fields.
///
/// # Errors
/// Returns a [`ProofInputError`] if any check fails.
pub fn check_attestation_input_validity(
    inputs: &AttestationProofCircuitInput,
) -> Result<(), ProofInputError> {
    check_token_freshness(
        "AAT",
        inputs.aat_claims.exp,
        inputs.now,
        MAX_AAT_LIFETIME_SECS,
    )?;
    check_token_freshness(
        "TAKT",
        inputs.takt_claims.exp,
        inputs.now,
        MAX_TAKT_LIFETIME_SECS,
    )?;
    Ok(())
}

/// Generates an attestation proof using the provided prover.
///
/// # Errors
/// Returns [`ProofError`] if witness generation or proving fails.
pub fn generate_attestation_proof_with_prover(
    input: AttestationProofCircuitInput,
    prover: provekit_common::Prover,
) -> Result<NoirProof, ProofError> {
    check_attestation_input_validity(&input)?;
    provekit_common::register_ntt();

    let witness = input.into_witness()?;
    prover
        .prove(witness)
        .map_err(|e| ProofError::GenerationError(e.to_string()))
}

/// Verifies an attestation proof; callers must check the proof's public inputs
/// against their expectations.
///
/// # Errors
/// Returns [`ProofError`] if verification fails.
pub fn verify_attestation_proof_with_verifier(
    proof: &NoirProof,
    verifier: &mut provekit_common::Verifier,
) -> Result<(), ProofError> {
    provekit_common::register_ntt();
    verifier
        .verify(proof)
        .map_err(|e| ProofError::Verification(e.to_string()))
}

/// Maps a byte array to a Noir `[u8; N]` input value.
fn bytes_to_noir(bytes: &[u8]) -> InputValue {
    InputValue::Vec(
        bytes
            .iter()
            .map(|b| InputValue::Field(NoirElement::from(u64::from(*b))))
            .collect(),
    )
}

impl NoirCircuitInput for AttestationProofCircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let (assertion_key_x, assertion_key_y) =
            assertion_key_coordinates(&self.takt_claims.assertion_key)
                .map_err(|e| ProofError::GenerationError(e.to_string()))?;

        let mut map = InputMap::new();

        // Public inputs, derived from the token fields so the bindings hold by construction.
        map.insert(
            "trust_anchor_key_x".into(),
            InputValue::Field(NoirElement::from_repr(self.trust_anchor_key.x)),
        );
        map.insert(
            "trust_anchor_key_y".into(),
            InputValue::Field(NoirElement::from_repr(self.trust_anchor_key.y)),
        );
        map.insert(
            "now".into(),
            InputValue::Field(NoirElement::from(u64::from(self.now))),
        );
        map.insert(
            "aud".into(),
            InputValue::Field(NoirElement::from(self.aat_claims.aud.into_inner())),
        );
        map.insert("nonce".into(), self.aat_claims.nonce.into_noir_value());
        map.insert("cdh".into(), self.aat_claims.cdh.into_noir_value());
        map.insert(
            "authenticator_meta".into(),
            InputValue::Field(NoirElement::from(
                self.aat_claims.authenticator_meta.packed(),
            )),
        );
        map.insert(
            "sec_flags".into(),
            InputValue::Field(NoirElement::from(self.takt_claims.sec_flags())),
        );

        let mut aat: BTreeMap<String, InputValue> = BTreeMap::new();
        aat.insert(
            "aud".into(),
            InputValue::Field(NoirElement::from(self.aat_claims.aud.into_inner())),
        );
        aat.insert(
            "exp".into(),
            InputValue::Field(NoirElement::from(u64::from(self.aat_claims.exp))),
        );
        aat.insert("nonce".into(), self.aat_claims.nonce.into_noir_value());
        aat.insert("cdh".into(), self.aat_claims.cdh.into_noir_value());
        aat.insert(
            "authenticator_meta".into(),
            InputValue::Field(NoirElement::from(
                self.aat_claims.authenticator_meta.packed(),
            )),
        );
        aat.insert("signature".into(), bytes_to_noir(&self.aat_signature));
        map.insert("aat".into(), InputValue::Struct(aat));

        let mut takt: BTreeMap<String, InputValue> = BTreeMap::new();
        takt.insert(
            "exp".into(),
            InputValue::Field(NoirElement::from(u64::from(self.takt_claims.exp))),
        );
        takt.insert("assertion_key_x".into(), bytes_to_noir(&assertion_key_x));
        takt.insert("assertion_key_y".into(), bytes_to_noir(&assertion_key_y));
        takt.insert(
            "sec_flags".into(),
            InputValue::Field(NoirElement::from(self.takt_claims.sec_flags())),
        );
        // babyjubjub scalar → bn254 scalar via big-endian bytes
        let s_native = ark_bn254::Fr::from_be_bytes_mod_order(
            &self.takt_signature.s.into_bigint().to_bytes_be(),
        );
        takt.insert(
            "sig_s".into(),
            InputValue::Field(NoirElement::from_repr(s_native)),
        );
        takt.insert(
            "sig_r".into(),
            InputValue::Vec(vec![
                InputValue::Field(NoirElement::from_repr(self.takt_signature.r.x)),
                InputValue::Field(NoirElement::from_repr(self.takt_signature.r.y)),
            ]),
        );
        map.insert("takt".into(), InputValue::Struct(takt));

        Ok(map)
    }
}

#[cfg(all(
    test,
    feature = "embed-attestation-prover",
    feature = "embed-attestation-verifier"
))]
mod proving_tests {
    use super::*;
    use crate::{artifacts::embedded::noir, fixtures::attestation_proof_fixture};

    /// End-to-end prove + verify, with a tampered-public-input negative control.
    #[test]
    fn test_proves_and_verifies_the_fixture() {
        let prover = noir::load_embedded_attestation_prover().expect("embedded prover");
        let mut verifier = noir::load_embedded_attestation_verifier().expect("embedded verifier");

        let proof = generate_attestation_proof_with_prover(attestation_proof_fixture(), prover)
            .expect("attestation proof generation");
        verify_attestation_proof_with_verifier(&proof, &mut verifier)
            .expect("attestation proof verifies");

        // Negative control: flipping `now` (public input index 2) must fail.
        let mut tampered = proof;
        tampered.public_inputs.0[2] += ark_bn254::Fr::from(1u64);
        verify_attestation_proof_with_verifier(&tampered, &mut verifier)
            .expect_err("tampered public input must not verify");
    }
}

#[cfg(test)]
mod input_validation_tests {
    use super::*;
    use crate::fixtures::attestation_proof_fixture;

    #[test]
    fn test_accepts_the_valid_fixture() {
        check_attestation_input_validity(&attestation_proof_fixture()).expect("fixture is valid");
    }

    #[test]
    fn test_rejects_expired_aat() {
        let mut input = attestation_proof_fixture();
        input.now = input.aat_claims.exp;

        let err = check_attestation_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::TokenExpired { token: "AAT", .. }
        ));
    }

    #[test]
    fn test_rejects_aat_exceeding_max_lifetime() {
        let mut input = attestation_proof_fixture();
        input.now = input.aat_claims.exp - MAX_AAT_LIFETIME_SECS - 1;

        let err = check_attestation_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::TokenLifetimeExceeded { token: "AAT", .. }
        ));
    }

    #[test]
    fn test_rejects_takt_exceeding_max_lifetime() {
        let mut input = attestation_proof_fixture();
        input.takt_claims.exp = input.now + MAX_TAKT_LIFETIME_SECS + 1;

        let err = check_attestation_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::TokenLifetimeExceeded { token: "TAKT", .. }
        ));
    }

    #[test]
    fn test_rejects_exp_below_fixed_width_range() {
        let mut input = attestation_proof_fixture();
        input.aat_claims.exp = u32::from(u16::MAX);
        input.now = 1;

        let err = check_attestation_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::TokenExpirationOutOfRange { token: "AAT", .. }
        ));
    }

    /// Pins the witness keys to the circuit ABI; drift would otherwise fail only at proving time.
    #[test]
    fn test_witness_matches_the_circuit_abi() {
        let witness = attestation_proof_fixture().into_witness().expect("witness");

        let keys: Vec<&str> = witness.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "aat",
                "aud",
                "authenticator_meta",
                "cdh",
                "nonce",
                "now",
                "sec_flags",
                "takt",
                "trust_anchor_key_x",
                "trust_anchor_key_y",
            ]
        );
    }
}
