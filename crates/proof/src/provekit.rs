//! Circuit-independent ProveKit helpers shared by the Noir proofs: loading provers and verifiers,
//! proving a witness, and verifying a proof against its public inputs.

use std::io::Read;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

#[cfg(any(
    target_arch = "wasm32",
    all(
        test,
        feature = "embed-ownership-prover",
        feature = "embed-ownership-verifier"
    )
))]
use acvm::{
    acir::native_types::WitnessMap,
    pwg::{ACVM, ACVMStatus},
};
#[cfg(any(
    target_arch = "wasm32",
    all(
        test,
        feature = "embed-ownership-prover",
        feature = "embed-ownership-verifier"
    )
))]
use bn254_blackbox_solver::Bn254BlackBoxSolver;
#[cfg(any(
    target_arch = "wasm32",
    all(
        test,
        feature = "embed-ownership-prover",
        feature = "embed-ownership-verifier"
    )
))]
use provekit_common::NoirElement;
use provekit_common::{InputMap, WhirR1CSProof};
#[cfg(not(target_arch = "wasm32"))]
use provekit_common::{NoirProof, PublicInputs};
use provekit_prover::Prove;
#[cfg(not(target_arch = "wasm32"))]
use provekit_verifier::Verify;
#[cfg(not(target_arch = "wasm32"))]
use world_id_primitives::FieldElement;

use crate::ProofError;

/// Loads a prover from a reader containing PKP bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the prover cannot be deserialized.
pub(crate) fn load_prover_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;

    #[cfg(not(target_arch = "wasm32"))]
    {
        provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
    }
    #[cfg(target_arch = "wasm32")]
    {
        deserialize_prover(&bytes)
    }
}

/// Decodes PKP bytes like `provekit_common::file::deserialize`, but in pure Rust: provekit's
/// decoder links the C zstd and xz libraries, which don't build for wasm32. ProveKit always writes
/// provers xz-compressed.
#[cfg(any(
    target_arch = "wasm32",
    all(
        test,
        feature = "embed-ownership-prover",
        feature = "embed-ownership-verifier"
    )
))]
fn deserialize_prover(bytes: &[u8]) -> eyre::Result<provekit_common::Prover> {
    const MAGIC: &[u8] = b"\xDC\xDFOZkp\x01\x00";
    const FORMAT: &[u8] = b"PrvKitPr";
    const VERSION: (u16, u16) = (1, 1);
    const XZ_MAGIC: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

    let (header, compressed) = bytes
        .split_at_checked(20)
        .ok_or_else(|| eyre::eyre!("prover file is too short"))?;
    eyre::ensure!(
        &header[..8] == MAGIC && &header[8..16] == FORMAT,
        "not a ProveKit prover file"
    );
    let major = u16::from_le_bytes([header[16], header[17]]);
    let minor = u16::from_le_bytes([header[18], header[19]]);
    eyre::ensure!(
        major == VERSION.0 && minor >= VERSION.1,
        "unsupported prover file version {major}.{minor}"
    );
    eyre::ensure!(
        compressed.starts_with(XZ_MAGIC),
        "prover file is not xz-compressed"
    );

    let mut decompressed = Vec::new();
    lzma_rs::xz_decompress(&mut &compressed[..], &mut decompressed)
        .map_err(|e| eyre::eyre!("while decompressing the prover: {e}"))?;
    postcard::from_bytes(&decompressed).map_err(|e| eyre::eyre!("while decoding the prover: {e}"))
}

/// Loads a prover from a PKP file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the prover cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn load_prover_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a verifier from a reader containing PKV bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the verifier cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn load_verifier_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a verifier from a PKV file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the verifier cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn load_verifier_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Proves `witness`. On wasm32 the witness is solved with [`solve_witness`] first, since
/// `Prove::prove` solves it through `nargo`, which does not build there.
///
/// # Errors
/// Returns [`ProofError::GenerationError`] if witness generation or proving fails.
pub(crate) fn prove(
    prover: provekit_common::Prover,
    witness: InputMap,
) -> Result<WhirR1CSProof, ProofError> {
    provekit_common::register_ntt();

    #[cfg(target_arch = "wasm32")]
    let witness = solve_witness(&prover, witness)?;
    #[cfg(target_arch = "wasm32")]
    let noir_proof = prover.prove_with_witness(witness);
    #[cfg(not(target_arch = "wasm32"))]
    let noir_proof = prover.prove(witness);
    noir_proof
        .map(|noir_proof| noir_proof.whir_r1cs_proof)
        .map_err(|e| ProofError::GenerationError(e.to_string()))
}

/// Verifies `proof` against `public_inputs`, given in the order of the circuit's public
/// parameters.
///
/// # Errors
/// Returns [`ProofError::Verification`] if the proof bytes are malformed or verification fails.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn verify(
    verifier: &mut provekit_common::Verifier,
    public_inputs: &[FieldElement],
    proof: &WhirR1CSProof,
) -> Result<(), ProofError> {
    provekit_common::register_ntt();

    let noir_proof = NoirProof {
        public_inputs: PublicInputs::from_vec(public_inputs.iter().map(|input| **input).collect()),
        whir_r1cs_proof: proof.clone(),
    };
    verifier
        .verify(&noir_proof)
        .map_err(|e| ProofError::Verification(e.to_string()))
}

/// Solves the circuit witness with ACVM directly rather than through `nargo`, which
/// `Prove::prove` uses and which does not build for wasm32.
///
/// Supports single-function circuits without foreign or ACIR calls.
///
/// Errors never include witness values: they are private inputs.
///
/// # Errors
/// Returns [`ProofError::GenerationError`] if the inputs don't satisfy the circuit.
#[cfg(any(
    target_arch = "wasm32",
    all(
        test,
        feature = "embed-ownership-prover",
        feature = "embed-ownership-verifier"
    )
))]
pub(crate) fn solve_witness(
    prover: &provekit_common::Prover,
    input: InputMap,
) -> Result<WitnessMap<NoirElement>, ProofError> {
    let generation_error = |reason: &str| ProofError::GenerationError(reason.to_string());

    let initial_witness = prover
        .witness_generator
        .abi()
        .encode(&input, None)
        .map_err(|_| generation_error("inputs do not match the circuit ABI"))?;
    let [circuit] = prover.program.functions.as_slice() else {
        return Err(generation_error("expected a single-function circuit"));
    };

    let solver = Bn254BlackBoxSolver;
    let mut acvm = ACVM::new(
        &solver,
        &circuit.opcodes,
        initial_witness,
        &prover.program.unconstrained_functions,
        &circuit.assert_messages,
    );
    match acvm.solve() {
        ACVMStatus::Solved => Ok(acvm.finalize()),
        ACVMStatus::Failure(_) => Err(generation_error("inputs do not satisfy the circuit")),
        _ => Err(generation_error(
            "circuit requires a foreign or ACIR call, which is unsupported",
        )),
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "embed-ownership-prover",
    feature = "embed-ownership-verifier"
))]
mod tests {
    use super::*;

    const PKP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkp"));

    #[test]
    fn test_prover_decoder_matches_provekit() {
        let decoded = deserialize_prover(PKP_BYTES).expect("embedded prover decodes");
        let expected: provekit_common::Prover =
            provekit_common::file::deserialize(PKP_BYTES).expect("provekit decodes the prover");

        assert_eq!(
            postcard::to_allocvec(&decoded).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
    }

    #[test]
    fn test_native_prover_reader_accepts_zstd() {
        let expected: provekit_common::Prover =
            provekit_common::file::deserialize(PKP_BYTES).expect("provekit decodes the prover");
        let serialized = postcard::to_allocvec(&expected).unwrap();
        let mut zstd_pkp = PKP_BYTES[..20].to_vec();
        zstd_pkp.extend(zstd::stream::encode_all(serialized.as_slice(), 3).unwrap());

        let decoded = load_prover_from_reader(zstd_pkp.as_slice())
            .expect("native reader accepts zstd-compressed provers");
        assert_eq!(postcard::to_allocvec(&decoded).unwrap(), serialized);
    }

    #[test]
    fn test_prover_decoder_rejects_other_files() {
        let pkv = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkv"));
        assert!(deserialize_prover(pkv).is_err());
        assert!(deserialize_prover(&PKP_BYTES[..20]).is_err());

        let mut wrong_version = PKP_BYTES.to_vec();
        wrong_version[16] = 2;
        assert!(deserialize_prover(&wrong_version).is_err());
    }
}
