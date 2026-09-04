//! WebAuthn passkey ownership proof support (unaudited demo circuit).
//!
//! The circuit proves control of an ES256/P-256 passkey committed in a
//! `WorldIDRegistryV2` account leaf. The checked-in native artifacts use the
//! ProveKit V1 artifact format and Noir beta.11; they are embedded only when
//! the `embed-passkey-prover` / `embed-passkey-verifier` features are enabled.
//! The browser demo under `apps/passkey-demo` carries a separate PKP 2.0 /
//! PKV 2.1 build of the same statement for the published WASM SDK.

use std::collections::BTreeMap;

use ark_ff::{BigInteger as _, PrimeField as _};
use provekit_common::{InputMap, InputValue, NoirElement, NoirProof, Prover, Verifier};
use provekit_prover::Prove as _;
use provekit_verifier::Verify as _;
use sha2::{Digest as _, Sha256};
use world_id_primitives::{FieldElement, TREE_DEPTH};

use crate::{NoirCircuitInput, NoirRepresentable, ProofError};

/// Number of authenticator slots committed by the registry account leaf.
pub const PASSKEY_OWNERSHIP_NUM_SLOTS: usize = 7;
/// Maximum `clientDataJSON` byte length accepted by the circuit.
pub const CLIENT_DATA_JSON_MAX_LEN: usize = 256;
/// Maximum `authenticatorData` byte length accepted by the circuit.
pub const AUTHENTICATOR_DATA_MAX_LEN: usize = 64;
/// Fixed action domain mixed into every proof-request challenge.
pub const PROOF_REQUEST_ACTION: &[u8] = b"world-id-proof-v1";

/// Derives the WebAuthn challenge the circuit expects for a proof request.
///
/// Mirrors the in-circuit derivation
/// `SHA-256(pad32(action) || rp_id_hash || root_be32 || nonce)`, which binds the
/// signed challenge to the action domain, relying party, registry root, and nonce.
#[must_use]
pub fn proof_request_challenge(
    rp_id_hash: &[u8; 32],
    root: &FieldElement,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut action = [0u8; 32];
    action[..PROOF_REQUEST_ACTION.len()].copy_from_slice(PROOF_REQUEST_ACTION);
    let root_bytes = root.into_bigint().to_bytes_be();

    let mut hasher = Sha256::new();
    hasher.update(action);
    hasher.update(rp_id_hash);
    hasher.update(root_bytes);
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Raw WebAuthn values consumed by the passkey circuit.
#[derive(Debug, Clone)]
pub struct WebAuthnWitness {
    /// P-256 public key x-coordinate in big-endian form.
    pub public_key_x: [u8; 32],
    /// P-256 public key y-coordinate in big-endian form.
    pub public_key_y: [u8; 32],
    /// Raw P-256 ECDSA signature encoded as `r || s`.
    pub signature: [u8; 64],
    /// Raw WebAuthn `clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// Raw WebAuthn `authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// Byte offset of the base64url challenge in `clientDataJSON`.
    pub challenge_index: u32,
}

/// Inputs for proving passkey control and World ID registry inclusion.
#[derive(Debug, Clone)]
pub struct PasskeyOwnershipCircuitInput {
    /// Public World ID registry root.
    pub root: FieldElement,
    /// Public WebAuthn challenge; must equal [`proof_request_challenge`].
    pub challenge: [u8; 32],
    /// Public SHA-256 RP ID hash.
    pub rp_id_hash: [u8; 32],
    /// Public SHA-256 of the exact expected WebAuthn origin, including port.
    pub origin_hash: [u8; 32],
    /// Public proof-request nonce.
    pub nonce: [u8; 32],
    /// Private WebAuthn assertion values.
    pub webauthn: WebAuthnWitness,
    /// Private mixed-authenticator slot commitments.
    pub slot_commitments: [FieldElement; PASSKEY_OWNERSHIP_NUM_SLOTS],
    /// Private slot containing the passkey commitment.
    pub passkey_slot_index: u32,
    /// Private account leaf index.
    pub leaf_index: u32,
    /// Private registry Merkle siblings.
    pub siblings: [FieldElement; TREE_DEPTH],
}

fn u32_value(value: u32) -> InputValue {
    InputValue::Field(NoirElement::from(value))
}

fn bytes_value(bytes: impl IntoIterator<Item = u8>) -> InputValue {
    InputValue::Vec(
        bytes
            .into_iter()
            .map(|byte| u32_value(byte.into()))
            .collect(),
    )
}

fn fields_value(fields: impl IntoIterator<Item = FieldElement>) -> InputValue {
    InputValue::Vec(
        fields
            .into_iter()
            .map(NoirRepresentable::into_noir_value)
            .collect(),
    )
}

/// Encodes `bytes` as a Noir `BoundedVec<u8, max_len>`.
fn bounded_bytes_value(bytes: &[u8], max_len: usize, name: &str) -> Result<InputValue, ProofError> {
    if bytes.len() > max_len {
        return Err(ProofError::GenerationError(format!(
            "{name} exceeds the circuit maximum of {max_len} bytes"
        )));
    }

    let mut storage = vec![0u8; max_len];
    storage[..bytes.len()].copy_from_slice(bytes);
    Ok(InputValue::Struct(BTreeMap::from([
        ("storage".into(), bytes_value(storage)),
        (
            "len".into(),
            InputValue::Field(NoirElement::from(bytes.len())),
        ),
    ])))
}

impl NoirCircuitInput for PasskeyOwnershipCircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        if usize::try_from(self.passkey_slot_index)
            .ok()
            .is_none_or(|index| index >= PASSKEY_OWNERSHIP_NUM_SLOTS)
        {
            return Err(ProofError::GenerationError(
                "passkey slot index is outside the circuit slot set".into(),
            ));
        }

        let webauthn = BTreeMap::from([
            (
                "public_key_x".into(),
                bytes_value(self.webauthn.public_key_x),
            ),
            (
                "public_key_y".into(),
                bytes_value(self.webauthn.public_key_y),
            ),
            ("signature".into(), bytes_value(self.webauthn.signature)),
            (
                "client_data_json".into(),
                bounded_bytes_value(
                    &self.webauthn.client_data_json,
                    CLIENT_DATA_JSON_MAX_LEN,
                    "clientDataJSON",
                )?,
            ),
            (
                "authenticator_data".into(),
                bounded_bytes_value(
                    &self.webauthn.authenticator_data,
                    AUTHENTICATOR_DATA_MAX_LEN,
                    "authenticatorData",
                )?,
            ),
            (
                "challenge_index".into(),
                u32_value(self.webauthn.challenge_index),
            ),
        ]);
        let merkle_proof = BTreeMap::from([
            ("leaf_index".into(), u32_value(self.leaf_index)),
            ("siblings".into(), fields_value(self.siblings)),
        ]);
        let inputs = BTreeMap::from([
            ("webauthn".into(), InputValue::Struct(webauthn)),
            (
                "slot_commitments".into(),
                fields_value(self.slot_commitments),
            ),
            (
                "passkey_slot_index".into(),
                u32_value(self.passkey_slot_index),
            ),
            ("merkle_proof".into(), InputValue::Struct(merkle_proof)),
        ]);

        Ok(InputMap::from([
            ("root".into(), self.root.into_noir_value()),
            ("challenge".into(), bytes_value(self.challenge)),
            ("rp_id_hash".into(), bytes_value(self.rp_id_hash)),
            ("origin_hash".into(), bytes_value(self.origin_hash)),
            ("nonce".into(), bytes_value(self.nonce)),
            ("inputs".into(), InputValue::Struct(inputs)),
        ]))
    }
}

/// Generates a passkey ownership proof with the provided prover.
///
/// # Errors
/// Returns [`ProofError`] if the inputs are invalid or proving fails.
pub fn generate_passkey_ownership_proof_with_prover(
    input: PasskeyOwnershipCircuitInput,
    prover: Prover,
) -> Result<NoirProof, ProofError> {
    prover
        .prove(input.into_witness()?)
        .map_err(|error| ProofError::GenerationError(error.to_string()))
}

/// Verifies a passkey ownership proof with the provided verifier.
///
/// # Errors
/// Returns [`ProofError::Verification`] if the proof does not verify.
pub fn verify_passkey_ownership_proof_with_verifier(
    proof: &NoirProof,
    verifier: &mut Verifier,
) -> Result<(), ProofError> {
    verifier
        .verify(proof)
        .map_err(|error| ProofError::Verification(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_derivation_matches_browser_vector() {
        // Same inputs as `apps/passkey-demo/tests/webauthn.test.ts`.
        let rp_id_hash: [u8; 32] = Sha256::digest(b"localhost").into();
        let nonce: [u8; 32] = std::array::from_fn(|index| index as u8);
        let challenge = proof_request_challenge(&rp_id_hash, &FieldElement::from(123u64), &nonce);
        let hex: String = challenge.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "78a66d000413695d3e0039af1d67d10ad117081c60605be0f76f70bcea96d54b"
        );
    }
}

/// Access to the checked-in native artifacts.
#[cfg(any(feature = "embed-passkey-prover", feature = "embed-passkey-verifier"))]
pub mod embedded {
    use super::{PasskeyOwnershipCircuitInput, ProofError};
    use provekit_common::{NoirProof, Prover, Verifier};

    #[cfg(feature = "embed-passkey-prover")]
    const PKP_BYTES: &[u8] =
        include_bytes!("../noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkp");

    #[cfg(feature = "embed-passkey-verifier")]
    const PKV_BYTES: &[u8] =
        include_bytes!("../noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkv");

    /// Loads the checked-in passkey prover.
    ///
    /// # Errors
    /// Returns an error if the embedded PKP cannot be deserialized.
    #[cfg(feature = "embed-passkey-prover")]
    pub fn load_embedded_passkey_prover() -> eyre::Result<Prover> {
        crate::ownership_proof::load_ownership_prover_from_reader(PKP_BYTES)
    }

    /// Loads the checked-in passkey verifier.
    ///
    /// # Errors
    /// Returns an error if the embedded PKV cannot be deserialized.
    #[cfg(feature = "embed-passkey-verifier")]
    pub fn load_embedded_passkey_verifier() -> eyre::Result<Verifier> {
        crate::ownership_proof::load_ownership_verifier_from_reader(PKV_BYTES)
    }

    /// Generates a passkey ownership proof using the checked-in prover.
    ///
    /// # Errors
    /// Returns [`ProofError`] if the prover cannot be loaded or proving fails.
    #[cfg(feature = "embed-passkey-prover")]
    pub fn generate_passkey_ownership_proof(
        input: PasskeyOwnershipCircuitInput,
    ) -> Result<NoirProof, ProofError> {
        let prover = load_embedded_passkey_prover()?;
        super::generate_passkey_ownership_proof_with_prover(input, prover)
    }

    /// Verifies a passkey ownership proof using the checked-in verifier.
    ///
    /// # Errors
    /// Returns [`ProofError`] if the verifier cannot be loaded or the proof is invalid.
    #[cfg(feature = "embed-passkey-verifier")]
    pub fn verify_passkey_ownership_proof(proof: &NoirProof) -> Result<(), ProofError> {
        let mut verifier = load_embedded_passkey_verifier()?;
        super::verify_passkey_ownership_proof_with_verifier(proof, &mut verifier)
    }

    #[cfg(all(
        test,
        feature = "embed-passkey-prover",
        feature = "embed-passkey-verifier"
    ))]
    mod tests {
        use super::*;

        #[test]
        fn embedded_artifacts_load_with_pinned_provekit_v1() {
            let prover = load_embedded_passkey_prover().expect("embedded passkey prover");
            let _verifier = load_embedded_passkey_verifier().expect("embedded passkey verifier");
            assert!(prover.size().0 > 300_000);
        }
    }
}

#[cfg(any(feature = "embed-passkey-prover", feature = "embed-passkey-verifier"))]
pub use embedded::*;
