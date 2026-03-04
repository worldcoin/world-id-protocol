//! Mobile benchmarks for World ID ZK proof generation.
//!
//! This crate provides benchmarks for the two main ZK proof generation functions:
//! - Query Proof (`π1`) - proves knowledge of a valid OPRF query
//! - Nullifier/Uniqueness Proof (`π2`) - proves uniqueness without revealing identity

use mobench_sdk::benchmark;

mod fixtures;

use ark_babyjubjub::Fq;
use ark_ec::CurveGroup;
use eddsa_babyjubjub::EdDSAPrivateKey;
use groth16_material::circom::CircomGroth16Material;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{
    cell::RefCell,
    sync::atomic::{AtomicU64, Ordering},
};
use taceo_oprf::core::{
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOprfResponse, BlindingFactor},
};
use world_id_primitives::{
    authenticator::{oprf_query_digest, AuthenticatorPublicKeySet},
    circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
    FieldElement, TREE_DEPTH,
};
use world_id_proof::proof;

use fixtures::{first_leaf_merkle_path, generate_rp_fixture};

// ============================================================================
// Fixture Generation (deterministic for reproducible benchmarks)
// ============================================================================

/// Create a deterministic RNG for reproducible benchmarks
fn deterministic_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(42)
}

/// Generate a valid QueryProofCircuitInput for benchmarking
fn generate_query_input() -> (
    QueryProofCircuitInput<TREE_DEPTH>,
    CircomGroth16Material,
    ChaCha20Rng,
) {
    let mut rng = deterministic_rng();

    // Load embedded proving material
    let query_material =
        proof::load_embedded_query_material().expect("failed to load query material");

    // Create user keys
    let user_sk = EdDSAPrivateKey::random(&mut rng);
    let key_set = AuthenticatorPublicKeySet::new(vec![user_sk.public().clone()])
        .expect("valid key set");

    // Create merkle proof
    let leaf = key_set.leaf_hash();
    let (siblings, root) = first_leaf_merkle_path(leaf);
    let leaf_index = 1u64;

    // Generate RP fixture
    let rp_fixture = generate_rp_fixture(&mut rng);

    // Compute query hash
    let query_hash = oprf_query_digest(
        leaf_index,
        rp_fixture.action.into(),
        rp_fixture.world_rp_id.into(),
    );

    // Sign the query
    let signature = user_sk.sign(*query_hash);

    // Create blinding factor
    let blinding_factor = BlindingFactor::rand(&mut rng);

    let query_input = QueryProofCircuitInput::<TREE_DEPTH> {
        pk: key_set.as_affine_array(),
        pk_index: 0u64.into(),
        s: signature.s,
        r: signature.r,
        merkle_root: *root,
        depth: Fq::from(TREE_DEPTH as u64),
        mt_index: leaf_index.into(),
        siblings: siblings.map(|s| *s),
        beta: blinding_factor.beta(),
        rp_id: *FieldElement::from(rp_fixture.world_rp_id),
        action: rp_fixture.action,
        nonce: rp_fixture.nonce,
    };

    (query_input, query_material, rng)
}

/// Generate a valid NullifierProofCircuitInput for benchmarking
fn generate_nullifier_input() -> (
    NullifierProofCircuitInput<TREE_DEPTH>,
    CircomGroth16Material,
    ChaCha20Rng,
) {
    let mut rng = deterministic_rng();

    // Load embedded proving materials
    let query_material =
        proof::load_embedded_query_material().expect("failed to load query material");
    let nullifier_material = proof::load_embedded_nullifier_material()
        .expect("failed to load nullifier material");

    // Create user keys
    let user_sk = EdDSAPrivateKey::random(&mut rng);
    let key_set = AuthenticatorPublicKeySet::new(vec![user_sk.public().clone()])
        .expect("valid key set");

    // Create merkle proof
    let leaf = key_set.leaf_hash();
    let (siblings, root) = first_leaf_merkle_path(leaf);
    let leaf_index = 1u64;

    // Generate RP fixture
    let rp_fixture = generate_rp_fixture(&mut rng);

    // Compute query hash
    let query_hash = oprf_query_digest(
        leaf_index,
        rp_fixture.action.into(),
        rp_fixture.world_rp_id.into(),
    );

    // Sign the query
    let signature = user_sk.sign(*query_hash);

    // Create blinding factor
    let blinding_factor = BlindingFactor::rand(&mut rng);

    // Create query input
    let query_input = QueryProofCircuitInput::<TREE_DEPTH> {
        pk: key_set.as_affine_array(),
        pk_index: 0u64.into(),
        s: signature.s,
        r: signature.r,
        merkle_root: *root,
        depth: Fq::from(TREE_DEPTH as u64),
        mt_index: leaf_index.into(),
        siblings: siblings.map(|s| *s),
        beta: blinding_factor.beta(),
        rp_id: *FieldElement::from(rp_fixture.world_rp_id),
        action: rp_fixture.action,
        nonce: rp_fixture.nonce,
    };

    // Generate query proof first (needed for nullifier input validation)
    let (_, _public) = query_material
        .generate_proof(&query_input, &mut rng)
        .expect("query proof generation");

    // Create issuer keys and credential
    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let credential_sub_blinding_factor = FieldElement::random(&mut rng);
    let credential_sub = world_id_primitives::credential::Credential::compute_sub(
        leaf_index,
        credential_sub_blinding_factor,
    );

    let genesis_issued_at = 1700000000u64; // Fixed timestamp for reproducibility
    let expires_at = genesis_issued_at + 86_400;

    let credential = world_id_primitives::credential::Credential::new()
        .issuer_schema_id(1)
        .subject(credential_sub)
        .genesis_issued_at(genesis_issued_at)
        .expires_at(expires_at)
        .sign(&issuer_sk)
        .expect("credential signing");

    let cred_signature = credential.signature.clone().expect("signed credential");

    // Simulate OPRF response
    let blinded_request =
        taceo_oprf::core::oprf::client::blind_query(*query_hash, blinding_factor.clone());
    let blinded_query = blinded_request.blinded_query();
    let blinded_response = (blinded_query * rp_fixture.rp_secret).into_affine();

    let blinding_factor_prepared = blinding_factor.prepare();
    let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
    let unblinded_response = oprf_blinded_response.unblind_response(&blinding_factor_prepared);

    // Create DLog equality proof
    let dlog_proof = DLogEqualityProof::proof(blinded_query, rp_fixture.rp_secret, &mut rng);

    let signal_hash = FieldElement::from_arbitrary_raw_bytes(b"benchmark signal");
    let session_id_r_seed = FieldElement::random(&mut rng);

    let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH> {
        query_input,
        issuer_schema_id: credential.issuer_schema_id.into(),
        cred_pk: credential.issuer.pk,
        cred_hashes: [
            *credential.claims_hash().expect("claims hash"),
            *credential.associated_data_hash,
        ],
        cred_genesis_issued_at: credential.genesis_issued_at.into(),
        cred_genesis_issued_at_min: 0u64.into(),
        cred_expires_at: credential.expires_at.into(),
        cred_id: credential.id.into(),
        cred_sub_blinding_factor: *credential_sub_blinding_factor,
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        id_commitment_r: *session_id_r_seed,
        id_commitment: Fq::from(0u64), // No session ID for benchmark
        dlog_e: dlog_proof.e,
        dlog_s: dlog_proof.s,
        oprf_pk: rp_fixture.rp_nullifier_point,
        oprf_response_blinded: blinded_response,
        oprf_response: unblinded_response,
        signal_hash: *signal_hash,
        current_timestamp: rp_fixture.current_timestamp.into(),
    };

    (nullifier_input, nullifier_material, rng)
}

// ============================================================================
// Benchmark Functions
// ============================================================================

/// Benchmark: Query Proof (π1) generation
///
/// This benchmarks the ZK proof generation for the OPRF query proof,
/// which proves knowledge of a valid signature and Merkle membership.
#[benchmark]
pub fn bench_query_proof_generation() {
    let (query_input, query_material, mut rng) = generate_query_input();

    let (proof, public) = query_material
        .generate_proof(&query_input, &mut rng)
        .expect("query proof generation");

    std::hint::black_box((proof, public));
}

const PROOF_ONLY_BASE_SEED: u64 = 0x5eed_5eed;
static PROOF_ONLY_COUNTER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static QUERY_PROOF_CACHE: RefCell<Option<(QueryProofCircuitInput<TREE_DEPTH>, CircomGroth16Material)>> =
        const { RefCell::new(None) };
    static QUERY_WITNESS_CACHE: RefCell<Option<(CircomGroth16Material, Vec<ark_bn254::Fr>)>> =
        const { RefCell::new(None) };
    static NULLIFIER_PROOF_CACHE: RefCell<Option<(NullifierProofCircuitInput<TREE_DEPTH>, CircomGroth16Material)>> =
        const { RefCell::new(None) };
    static NULLIFIER_WITNESS_CACHE: RefCell<Option<(CircomGroth16Material, Vec<ark_bn254::Fr>)>> =
        const { RefCell::new(None) };
}

/// Benchmark: Query Proof (π1) generation only
///
/// This benchmarks only the ZK proof generation step, with input and
/// proving material cached after the first call. Use warmup iterations
/// to keep setup cost out of measured samples.
#[benchmark]
pub fn bench_query_proof_only() {
    let iter = PROOF_ONLY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut rng = ChaCha20Rng::seed_from_u64(PROOF_ONLY_BASE_SEED ^ iter);

    QUERY_PROOF_CACHE.with(|cache| {
        if cache.borrow().is_none() {
            let (input, material, _rng) = generate_query_input();
            *cache.borrow_mut() = Some((input, material));
        }

        let cache_ref = cache.borrow();
        let (query_input, query_material) =
            cache_ref.as_ref().expect("query proof cache initialized");

        let (proof, public) = query_material
            .generate_proof(query_input, &mut rng)
            .expect("query proof generation");

        std::hint::black_box((proof, public));
    });
}

/// Benchmark: Query Proof (π1) witness generation only
///
/// Measures only Circom witness generation (R1CS assignment), excluding Groth16 proving.
/// Input and proving material are cached after the first call.
#[benchmark]
pub fn bench_query_witness_generation_only() {
    QUERY_PROOF_CACHE.with(|cache| {
        if cache.borrow().is_none() {
            let (input, material, _rng) = generate_query_input();
            *cache.borrow_mut() = Some((input, material));
        }

        let cache_ref = cache.borrow();
        let (query_input, query_material) =
            cache_ref.as_ref().expect("query proof cache initialized");

        let witness = query_material
            .generate_witness(query_input)
            .expect("query witness generation");

        std::hint::black_box(witness);
    });
}

/// Benchmark: Query Proof (π1) proving only (from cached witness)
///
/// Measures only Groth16 proving, excluding witness generation.
#[benchmark]
pub fn bench_query_proving_only() {
    let iter = PROOF_ONLY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut rng = ChaCha20Rng::seed_from_u64(PROOF_ONLY_BASE_SEED ^ iter ^ 0x5157_4E35);

    QUERY_WITNESS_CACHE.with(|cache| {
        if cache.borrow().is_none() {
            let (input, material, _rng) = generate_query_input();
            let witness = material
                .generate_witness(&input)
                .expect("query witness generation");
            *cache.borrow_mut() = Some((material, witness));
        }

        let cache_ref = cache.borrow();
        let (query_material, witness) =
            cache_ref.as_ref().expect("query witness cache initialized");

        let (proof, public) = query_material
            .generate_proof_from_witness(witness, &mut rng)
            .expect("query proof generation (from witness)");

        std::hint::black_box((proof, public));
    });
}

/// Benchmark: Nullifier/Uniqueness Proof (π2) generation
///
/// This benchmarks the ZK proof generation for the nullifier proof,
/// which is the more complex proof that ensures uniqueness.
#[benchmark]
pub fn bench_nullifier_proof_generation() {
    let (nullifier_input, nullifier_material, mut rng) = generate_nullifier_input();

    let (proof, public) = nullifier_material
        .generate_proof(&nullifier_input, &mut rng)
        .expect("nullifier proof generation");

    std::hint::black_box((proof, public));
}

/// Benchmark: Nullifier/Uniqueness Proof (π2) witness generation only
///
/// Measures only Circom witness generation (R1CS assignment), excluding Groth16 proving.
/// Input and proving material are cached after the first call.
#[benchmark]
pub fn bench_nullifier_witness_generation_only() {
    NULLIFIER_PROOF_CACHE.with(|cache| {
        if cache.borrow().is_none() {
            let (input, material, _rng) = generate_nullifier_input();
            *cache.borrow_mut() = Some((input, material));
        }

        let cache_ref = cache.borrow();
        let (nullifier_input, nullifier_material) = cache_ref
            .as_ref()
            .expect("nullifier proof cache initialized");

        let witness = nullifier_material
            .generate_witness(nullifier_input)
            .expect("nullifier witness generation");

        std::hint::black_box(witness);
    });
}

/// Benchmark: Nullifier/Uniqueness Proof (π2) proving only (from cached witness)
///
/// Measures only Groth16 proving, excluding witness generation.
#[benchmark]
pub fn bench_nullifier_proving_only() {
    let iter = PROOF_ONLY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut rng = ChaCha20Rng::seed_from_u64(PROOF_ONLY_BASE_SEED ^ iter ^ 0x5052_4F56);

    NULLIFIER_WITNESS_CACHE.with(|cache| {
        if cache.borrow().is_none() {
            let (input, material, _rng) = generate_nullifier_input();
            let witness = material
                .generate_witness(&input)
                .expect("nullifier witness generation");
            *cache.borrow_mut() = Some((material, witness));
        }

        let cache_ref = cache.borrow();
        let (nullifier_material, witness) = cache_ref
            .as_ref()
            .expect("nullifier witness cache initialized");

        let (proof, public) = nullifier_material
            .generate_proof_from_witness(witness, &mut rng)
            .expect("nullifier proof generation (from witness)");

        std::hint::black_box((proof, public));
    });
}

// ============================================================================
// UniFFI Exports for Mobile
// ============================================================================

/// Benchmark specification for mobile execution
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchSpec {
    pub name: String,
    pub iterations: u32,
    pub warmup: u32,
}

/// A single benchmark sample
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchSample {
    pub duration_ns: u64,
}

/// Benchmark report with timing results
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchReport {
    pub spec: BenchSpec,
    pub samples: Vec<BenchSample>,
}

/// Error types for benchmark operations
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum BenchError {
    #[error("unknown benchmark function: {name}")]
    UnknownFunction { name: String },

    #[error("benchmark execution failed: {reason}")]
    ExecutionFailed { reason: String },
}

uniffi::setup_scaffolding!();

/// Run a benchmark by name
#[uniffi::export]
pub fn run_benchmark(spec: BenchSpec) -> Result<BenchReport, BenchError> {
    let sdk_spec = mobench_sdk::BenchSpec {
        name: spec.name.clone(),
        iterations: spec.iterations,
        warmup: spec.warmup,
    };

    let report = mobench_sdk::run_benchmark(sdk_spec).map_err(|e| match e {
        mobench_sdk::BenchError::UnknownFunction(name, _available) => {
            BenchError::UnknownFunction { name }
        }
        other => BenchError::ExecutionFailed {
            reason: other.to_string(),
        },
    })?;

    Ok(BenchReport {
        spec,
        samples: report
            .samples
            .into_iter()
            .map(|s| BenchSample {
                duration_ns: s.duration_ns,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_proof_benchmark() {
        // Just verify the benchmark runs without panicking
        bench_query_proof_generation();
    }

    #[test]
    fn test_query_proof_only_benchmark() {
        // Just verify the benchmark runs without panicking
        bench_query_proof_only();
    }

    #[test]
    fn test_nullifier_proof_benchmark() {
        // Just verify the benchmark runs without panicking
        bench_nullifier_proof_generation();
    }

    #[test]
    fn test_query_witness_only_benchmark() {
        bench_query_witness_generation_only();
    }

    #[test]
    fn test_query_proving_only_benchmark() {
        bench_query_proving_only();
    }

    #[test]
    fn test_nullifier_witness_only_benchmark() {
        bench_nullifier_witness_generation_only();
    }

    #[test]
    fn test_nullifier_proving_only_benchmark() {
        bench_nullifier_proving_only();
    }

    #[test]
    fn test_run_benchmark_via_registry() {
        let benchmarks = mobench_sdk::discover_benchmarks();
        assert!(benchmarks.len() >= 3, "Should find at least 3 benchmarks");

        let spec = BenchSpec {
            name: "zk_mobile_bench::bench_query_proof_generation".to_string(),
            iterations: 1,
            warmup: 0,
        };
        let report = run_benchmark(spec).expect("benchmark should run");
        assert_eq!(report.samples.len(), 1);
    }
}
