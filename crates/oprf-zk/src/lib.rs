//! Zero-Knowledge proof helpers and Groth16 material for OPRF client.
//!
//! This module provides everything necessary to generate and verify
//! zero-knowledge proofs for OPRFQuery and OPRFNullifier Circom circuits.
//!
//! Key points:
//! - Holds Groth16 proving keys (`.zkey`) and their associated constraint matrices
//!   for both the OPRFQuery and OPRFNullifier circuits.
//! - Validates the fingerprint of the proving keys to prevent accidental use
//!   of wrong keys.
//! - Provides methods to generate proofs from prepared circuit inputs, and
//!   immediately verifies the generated proof against the verifying key.
//! - Includes helper functions to calculate witnesses and manage black-box
//!   functions required by Circom circuits.
//!
//! We refer to the current SHA-256 fingerprints for the zkeys:
//! - [`QUERY_FINGERPRINT`]
//! - [`NULLIFIER_FINGERPRINT`]

use std::ops::Shr;
use std::str::FromStr;
use std::{collections::HashMap, path::Path, sync::Arc};

use ark_bn254::Bn254;
use ark_ff::{AdditiveGroup as _, BigInt, Field as _, LegendreSymbol, UniformRand as _};
use circom_types::{groth16::ZKey, traits::CheckElement};
use groth16::{CircomReduction, ConstraintMatrices, Groth16, Proof, ProvingKey};
use k256::sha2::Digest as _;
use rand::{CryptoRng, Rng};
use witness::Graph;
use witness::{ruint::aliases::U256, BlackBoxFunction};

use crate::groth16_serde::Groth16Proof;

pub mod groth16_serde;
pub mod proof_inputs;

pub const QUERY_GRAPH_BYTES: &[u8] = include_bytes!("../../../circom/query_graph.bin");
pub const NULLIFIER_GRAPH_BYTES: &[u8] = include_bytes!("../../../circom/nullifier_graph.bin");

#[cfg(feature = "embed-zkeys")]
pub const QUERY_ZKEY_BYTES: &[u8] = include_bytes!("../../../circom/query.zkey");
#[cfg(feature = "embed-zkeys")]
pub const NULLIFIER_ZKEY_BYTES: &[u8] = include_bytes!("../../../circom/nullifier.zkey");

/// The SHA-256 fingerprint of the OPRFQuery ZKey.
pub const QUERY_FINGERPRINT: &str =
    "18e942559f5db90d86e1f24dfc3c79c486d01f6284ccca80fdb61a5cca9da16a";
/// The SHA-256 fingerprint of the OPRFNullifier ZKey.
pub const NULLIFIER_FINGERPRINT: &str =
    "69195d6c04b0751b03109641c0b8aaf9367af2c1740909406deaefd24440dfb2";

/// Errors that can occur while loading or parsing a `.zkey` or graph file.
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    /// Any I/O error encountered while reading the `.zkey` or graph file
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// The SHA-256 fingerprint of the `.zkey` did not match the expected value.
    #[error("invalid zkey - wrong sha256 fingerprint")]
    ZKeyFingerprintMismatch,
    /// Could not parse the `.zkey` file.
    #[error(transparent)]
    ZKeyInvalid(#[from] circom_types::ZKeyParserError),
    /// Could not parse the graph file.
    #[error(transparent)]
    GraphInvalid(#[from] eyre::Report),
    /// Failed to fetch the `.zkey` or graph from a remote source.
    #[error(transparent)]
    Network(#[from] reqwest::Error),
}

/// Errors that can occur during Groth16 proof generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum Groth16Error {
    /// Failed to generate a witness for the circuit.
    #[error("failed to generate witness")]
    WitnessGeneration,
    /// Failed to generate a Groth16 proof.
    #[error("failed to generate proof")]
    ProofGeneration,
    /// Generated proof could not be verified against the verification key.
    #[error("proof could not be verified")]
    InvalidProof,
}

/// Core material for generating zero-knowledge proofs.
///
/// Holds the proving keys, constraint matrices and graphs.
/// Provides methods to:
/// - Generate proofs from structured inputs
/// - Verify proofs internally immediately after generation
pub struct Groth16Material {
    /// Proving key for the OPRFQuery circuit
    pub pk: ProvingKey<Bn254>,
    /// Constraint matrices for the OPRFQuery circuit
    pub matrices: ConstraintMatrices<ark_bn254::Fr>,
    /// The graph for witness extension
    pub graph: Graph,
    /// The black-box functions needed for witness extension
    pub bbfs: HashMap<String, BlackBoxFunction>,
}

impl Groth16Material {
    /// Loads the Groth16 material from `.zkey` and graph files and verifies their fingerprints.
    ///
    /// # Arguments
    ///
    /// * `zkey_path` - Path to the `.zkey` file
    /// * `fingerprint` - Optional SHA-256 fingerprint to validate the `.zkey` file
    /// * `graph_path` - Path to the circuit graph file
    ///
    /// # Errors
    ///
    /// Returns a [`ZkError`] if the file cannot be read or the fingerprint
    /// does not match the expected value.
    pub fn new(
        zkey_path: impl AsRef<Path>,
        fingerprint: Option<&'static str>,
        graph_path: impl AsRef<Path>,
    ) -> Result<Self, ZkError> {
        let zkey_bytes = std::fs::read(zkey_path)?;
        let graph_bytes = std::fs::read(graph_path)?;
        Self::from_bytes(&zkey_bytes, fingerprint, &graph_bytes)
    }

    /// Builds Groth16 material directly from in-memory `.zkey` and graph bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`ZkError::ZKeyFingerprintMismatch`] if any embedded fingerprint check fails.
    pub fn from_bytes(
        zkey_bytes: &[u8],
        fingerprint: Option<&'static str>,
        graph_bytes: &[u8],
    ) -> Result<Self, ZkError> {
        let (matrices, pk) = if let Some(fingerprint) = fingerprint {
            parse_zkey_bytes(zkey_bytes, fingerprint)?
        } else {
            let query_zkey =
                ZKey::from_reader(zkey_bytes, CheckElement::No).map_err(ZkError::ZKeyInvalid)?;
            query_zkey.into()
        };
        let graph = witness::init_graph(graph_bytes).map_err(ZkError::GraphInvalid)?;
        Ok(Self {
            pk,
            matrices,
            graph,
            bbfs: black_box_functions(),
        })
    }

    /// Builds Groth16 material directly from `.zkey` and graph readers.
    ///
    /// # Errors
    ///
    /// Returns a [`ZkError::ZKeyFingerprintMismatch`] if any embedded fingerprint check fails.
    pub fn from_reader(
        mut zkey_reader: impl std::io::Read,
        fingerprint: Option<&'static str>,
        mut graph_reader: impl std::io::Read,
    ) -> Result<Self, ZkError> {
        let mut zkey_bytes = Vec::new();
        zkey_reader.read_to_end(&mut zkey_bytes)?;
        let mut graph_bytes = Vec::new();
        graph_reader.read_to_end(&mut graph_bytes)?;
        Self::from_bytes(&zkey_bytes, fingerprint, &graph_bytes)
    }

    /// Builds Groth16 material from embedded `.zkey` and graph bytes baked into the binary.
    ///
    /// # Errors
    ///
    /// Returns a [`ZkError::ZKeyFingerprintMismatch`] if the baked-in fingerprints
    /// and expected constants differ.
    #[cfg(feature = "embed-zkeys")]
    pub fn query_material() -> Result<Self, ZkError> {
        Self::from_bytes(
            QUERY_ZKEY_BYTES,
            QUERY_FINGERPRINT.into(),
            QUERY_GRAPH_BYTES,
        )
    }

    /// Builds Groth16 material from embedded `.zkey` and graph bytes baked into the binary.
    ///
    /// # Errors
    ///
    /// Returns a [`ZkError::ZKeyFingerprintMismatch`] if the baked-in fingerprints
    /// and expected constants differ.
    #[cfg(feature = "embed-zkeys")]
    pub fn nullifier_material() -> Result<Self, ZkError> {
        Self::from_bytes(
            NULLIFIER_ZKEY_BYTES,
            NULLIFIER_FINGERPRINT.into(),
            NULLIFIER_GRAPH_BYTES,
        )
    }

    /// Downloads `.zkey` and graph files from the provided URLs and builds the Groth16 material.
    ///
    /// # Errors
    ///
    /// Returns a [`ZkError::Network`] if fetching either URL fails, or a
    /// [`ZkError::ZKeyFingerprintMismatch`] if the downloaded bytes do not
    /// match the expected fingerprints.
    pub async fn from_urls(
        zkey_url: impl reqwest::IntoUrl,
        fingerprint: Option<&'static str>,
        graph_url: impl reqwest::IntoUrl,
    ) -> Result<Self, ZkError> {
        let zkey_bytes = reqwest::get(zkey_url).await?.bytes().await?;
        let graph_bytes = reqwest::get(graph_url).await?.bytes().await?;
        Self::from_bytes(&zkey_bytes, fingerprint, &graph_bytes)
    }

    /// Computes a witness vector from a circuit graph and inputs.
    pub fn generate_witness(
        &self,
        inputs: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Vec<ark_bn254::Fr>, Groth16Error> {
        let inputs = inputs
            .into_iter()
            .map(|(name, value)| (name, parse(value)))
            .collect();
        let witness = witness::calculate_witness(inputs, &self.graph, Some(&self.bbfs))
            .map_err(|err| {
                tracing::error!("error during calculate_witness: {err:?}");
                Groth16Error::WitnessGeneration
            })?
            .into_iter()
            .map(|v| ark_bn254::Fr::from(BigInt(v.into_limbs())))
            .collect::<Vec<_>>();
        Ok(witness)
    }

    /// Generates a Groth16 proof from a witness and verifies it.
    pub fn generate_proof<R: Rng + CryptoRng>(
        &self,
        witness: &[ark_bn254::Fr],
        rng: &mut R,
    ) -> Result<(Groth16Proof, Vec<ark_babyjubjub::Fq>), Groth16Error> {
        let r = ark_bn254::Fr::rand(rng);
        let s = ark_bn254::Fr::rand(rng);

        let proof = Groth16::prove::<CircomReduction>(&self.pk, r, s, &self.matrices, witness)
            .map_err(|err| {
                tracing::error!("error during prove: {err:?}");
                Groth16Error::ProofGeneration
            })?;

        let inputs = witness[1..self.matrices.num_instance_variables].to_vec();
        self.verify_proof(&proof, &inputs)?;

        Ok((Groth16Proof::from(proof), inputs))
    }

    pub fn verify_proof(
        &self,
        proof: &Proof<Bn254>,
        public_inputs: &[ark_bn254::Fr],
    ) -> Result<(), Groth16Error> {
        Groth16::verify(&self.pk.vk, proof, public_inputs).map_err(|err| {
            tracing::error!("error during verify: {err:?}");
            Groth16Error::InvalidProof
        })
    }
}

/// Loads a `.zkey` from memory and returns its matrices and proving key.
/// Checks the SHA-256 fingerprint.
fn parse_zkey_bytes(
    bytes: &[u8],
    should_fingerprint: &'static str,
) -> Result<(ConstraintMatrices<ark_bn254::Fr>, ProvingKey<Bn254>), ZkError> {
    let is_fingerprint = k256::sha2::Sha256::digest(bytes);

    if hex::encode(is_fingerprint) != should_fingerprint {
        return Err(ZkError::ZKeyFingerprintMismatch);
    }

    let query_zkey =
        ZKey::from_reader(bytes, CheckElement::No).expect("valid zkey if fingerprint matches");
    Ok(query_zkey.into())
}

fn black_box_functions() -> HashMap<String, BlackBoxFunction> {
    let mut bbfs: HashMap<String, BlackBoxFunction> = HashMap::new();
    bbfs.insert(
        "bbf_inv".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            // function bbf_inv(in) {
            //     return in!=0 ? 1/in : 0;
            // }
            args[0].inverse().unwrap_or(ark_bn254::Fr::ZERO)
        }),
    );
    bbfs.insert(
        "bbf_legendre".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            match args[0].legendre() {
                LegendreSymbol::Zero => ark_bn254::Fr::from(0u64),
                LegendreSymbol::QuadraticResidue => ark_bn254::Fr::from(1u64),
                LegendreSymbol::QuadraticNonResidue => -ark_bn254::Fr::from(1u64),
            }
        }),
    );
    bbfs.insert(
        "bbf_sqrt_unchecked".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            args[0].sqrt().unwrap_or(ark_bn254::Fr::ZERO)
        }),
    );
    bbfs.insert(
        "bbf_sqrt_input".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            // function bbf_sqrt_input(l, a, na) {
            //     if (l != -1) {
            //         return a;
            //     } else {
            //         return na;
            //     }
            // }
            if args[0] != -ark_bn254::Fr::ONE {
                args[1]
            } else {
                args[2]
            }
        }),
    );
    bbfs.insert(
        "bbf_num_2_bits_helper".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            // function bbf_num_2_bits_helper(in, i) {
            //     return (in >> i) & 1;
            // }
            let a: U256 = args[0].into();
            let b: U256 = args[1].into();
            let ls_limb = b.as_limbs()[0];
            ark_bn254::Fr::new((a.shr(ls_limb as usize) & U256::from(1)).into())
        }),
    );
    // the call to this function gets removed with circom --O2 optimization and circom-witness-rs can handle the optimized version without a bbf
    // bbfs.insert(
    //     "bbf_num_2_bits_neg_helper".to_string(),
    //     Arc::new(move |args: &[Fr]| -> Fr {
    //         // function bbf_num_2_bits_neg_helper(in, n) {
    //         //     return n == 0 ? 0 : 2**n - in;
    //         // }
    //         if args[1] == Fr::ZERO {
    //             Fr::ZERO
    //         } else {
    //             let a: U256 = args[1].into();
    //             let ls_limb = a.as_limbs()[0];
    //             let tmp: Fr = Fr::new((U256::from(1).shl(ls_limb as usize)).into());
    //             tmp - args[0]
    //         }
    //     }),
    // );
    bbfs
}

fn parse(value: serde_json::Value) -> Vec<U256> {
    match value {
        serde_json::Value::String(string) => {
            vec![U256::from_str(&string).expect("can deserialize field element")]
        }
        serde_json::Value::Array(values) => values.into_iter().flat_map(parse).collect(),
        _ => unimplemented!(),
    }
}
