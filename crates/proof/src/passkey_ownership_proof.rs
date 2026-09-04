//! WebAuthn passkey ownership proof support.
//!
//! The circuit proves control of an ES256/P-256 passkey committed in a
//! `WorldIDRegistryV2` account leaf. The checked-in artifacts use the ProveKit
//! V1 artifact format and Noir beta.11. The browser demo carries a separate
//! PKP 2.0/PKV 2.1 build of the same statement because its published WASM SDK
//! uses the beta.20 artifact graph.

use std::{collections::BTreeMap, io::Read, path::Path};

use provekit_common::{InputMap, InputValue, NoirElement, NoirProof};
use provekit_prover::Prove as _;
use provekit_verifier::Verify as _;
use world_id_primitives::{FieldElement, TREE_DEPTH};

use crate::{NoirCircuitInput, NoirRepresentable, ProofError};

/// Number of authenticator slots committed by the registry account leaf.
pub const PASSKEY_OWNERSHIP_NUM_SLOTS: usize = 7;
/// Maximum `clientDataJSON` byte length accepted by the circuit.
pub const CLIENT_DATA_JSON_MAX_LEN: usize = 256;
/// Maximum `authenticatorData` byte length accepted by the circuit.
pub const AUTHENTICATOR_DATA_MAX_LEN: usize = 64;

const EMBEDDED_PROVER: &[u8] =
    include_bytes!("../noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkp");
const EMBEDDED_VERIFIER: &[u8] =
    include_bytes!("../noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkv");

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
    /// Public WebAuthn challenge.
    pub challenge: [u8; 32],
    /// Public SHA-256 RP ID hash.
    pub rp_id_hash: [u8; 32],
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

fn bytes_value(bytes: impl IntoIterator<Item = u8>) -> InputValue {
    InputValue::Vec(
        bytes
            .into_iter()
            .map(|byte| InputValue::Field(NoirElement::from(u32::from(byte))))
            .collect(),
    )
}

fn bounded_bytes_value(bytes: &[u8], max_len: usize, name: &str) -> Result<InputValue, ProofError> {
    if bytes.len() > max_len {
        return Err(ProofError::GenerationError(format!(
            "{name} exceeds the circuit maximum of {max_len} bytes"
        )));
    }

    let mut storage = vec![0u8; max_len];
    storage[..bytes.len()].copy_from_slice(bytes);
    let mut value = BTreeMap::new();
    value.insert("storage".into(), bytes_value(storage));
    value.insert(
        "len".into(),
        InputValue::Field(NoirElement::from(bytes.len())),
    );
    Ok(InputValue::Struct(value))
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

        let mut map = InputMap::new();
        map.insert("root".into(), self.root.into_noir_value());
        map.insert("challenge".into(), bytes_value(self.challenge));
        map.insert("rp_id_hash".into(), bytes_value(self.rp_id_hash));

        let mut webauthn = BTreeMap::new();
        webauthn.insert(
            "public_key_x".into(),
            bytes_value(self.webauthn.public_key_x),
        );
        webauthn.insert(
            "public_key_y".into(),
            bytes_value(self.webauthn.public_key_y),
        );
        webauthn.insert("signature".into(), bytes_value(self.webauthn.signature));
        webauthn.insert(
            "client_data_json".into(),
            bounded_bytes_value(
                &self.webauthn.client_data_json,
                CLIENT_DATA_JSON_MAX_LEN,
                "clientDataJSON",
            )?,
        );
        webauthn.insert(
            "authenticator_data".into(),
            bounded_bytes_value(
                &self.webauthn.authenticator_data,
                AUTHENTICATOR_DATA_MAX_LEN,
                "authenticatorData",
            )?,
        );
        webauthn.insert(
            "challenge_index".into(),
            InputValue::Field(NoirElement::from(self.webauthn.challenge_index)),
        );

        let mut merkle = BTreeMap::new();
        merkle.insert(
            "leaf_index".into(),
            InputValue::Field(NoirElement::from(self.leaf_index)),
        );
        merkle.insert(
            "siblings".into(),
            InputValue::Vec(
                self.siblings
                    .into_iter()
                    .map(NoirRepresentable::into_noir_value)
                    .collect(),
            ),
        );

        let mut inputs = BTreeMap::new();
        inputs.insert("webauthn".into(), InputValue::Struct(webauthn));
        inputs.insert(
            "slot_commitments".into(),
            InputValue::Vec(
                self.slot_commitments
                    .into_iter()
                    .map(NoirRepresentable::into_noir_value)
                    .collect(),
            ),
        );
        inputs.insert(
            "passkey_slot_index".into(),
            InputValue::Field(NoirElement::from(self.passkey_slot_index)),
        );
        inputs.insert("merkle_proof".into(), InputValue::Struct(merkle));
        map.insert("inputs".into(), InputValue::Struct(inputs));

        Ok(map)
    }
}

/// Loads a passkey prover from PKP bytes.
pub fn load_passkey_prover_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|error| eyre::eyre!(error.to_string()))
}

/// Loads a passkey prover from a PKP path.
pub fn load_passkey_prover_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|error| eyre::eyre!(error.to_string()))
}

/// Loads the checked-in passkey prover.
pub fn load_embedded_passkey_prover() -> eyre::Result<provekit_common::Prover> {
    load_passkey_prover_from_reader(EMBEDDED_PROVER)
}

/// Loads a passkey verifier from PKV bytes.
pub fn load_passkey_verifier_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|error| eyre::eyre!(error.to_string()))
}

/// Loads a passkey verifier from a PKV path.
pub fn load_passkey_verifier_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|error| eyre::eyre!(error.to_string()))
}

/// Loads the checked-in passkey verifier.
pub fn load_embedded_passkey_verifier() -> eyre::Result<provekit_common::Verifier> {
    load_passkey_verifier_from_reader(EMBEDDED_VERIFIER)
}

/// Generates a passkey ownership proof using the checked-in prover.
pub fn generate_passkey_ownership_proof(
    input: PasskeyOwnershipCircuitInput,
) -> Result<NoirProof, ProofError> {
    let prover = load_embedded_passkey_prover()?;
    prover
        .prove(input.into_witness()?)
        .map_err(|error| ProofError::GenerationError(error.to_string()))
}

/// Verifies a passkey ownership proof using the checked-in verifier.
pub fn verify_passkey_ownership_proof(proof: &NoirProof) -> Result<(), ProofError> {
    let mut verifier = load_embedded_passkey_verifier()?;
    verifier
        .verify(proof)
        .map_err(|error| ProofError::Verification(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_artifacts_load_with_pinned_provekit_v1() {
        let prover = load_embedded_passkey_prover().expect("embedded passkey prover");
        let _verifier = load_embedded_passkey_verifier().expect("embedded passkey verifier");
        assert!(prover.size().0 > 300_000);
    }
}
