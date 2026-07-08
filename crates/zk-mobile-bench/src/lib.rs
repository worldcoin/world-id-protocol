//! Mobile benchmarks for World ID ZK proof generation.
//!
//! This crate provides benchmarks for the two main ZK proof generation functions:
//! - Query Proof (`π1`) - proves knowledge of a valid OPRF query
//! - Nullifier/Uniqueness Proof (`π2`) - proves uniqueness without revealing identity

use mobench_sdk::benchmark;

mod fixtures;

use ark_babyjubjub::Fq;
use ark_ec::CurveGroup;
use ark_ff::BigInt;
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
    AuthenticatorPublicKeySet, FieldElement, TREE_DEPTH, authenticator::oprf_query_digest,
};
use world_id_proof::{
    artifacts::embedded::zkeys,
    circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
};

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
        zkeys::load_embedded_query_material().expect("failed to load query material");

    // Create user keys
    let user_sk = EdDSAPrivateKey::random(&mut rng);
    let key_set =
        AuthenticatorPublicKeySet::new(vec![user_sk.public().clone()]).expect("valid key set");

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
        zkeys::load_embedded_query_material().expect("failed to load query material");
    let nullifier_material =
        zkeys::load_embedded_nullifier_material().expect("failed to load nullifier material");

    // Create user keys
    let user_sk = EdDSAPrivateKey::random(&mut rng);
    let key_set =
        AuthenticatorPublicKeySet::new(vec![user_sk.public().clone()]).expect("valid key set");

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
    let blinded_request = taceo_oprf::core::oprf::client::blind_query(*query_hash, blinding_factor);
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
            *credential.associated_data_commitment,
        ],
        cred_genesis_issued_at: credential.genesis_issued_at.into(),
        cred_genesis_issued_at_min: 0u64.into(),
        cred_expires_at: credential.expires_at.into(),
        cred_id: BigInt([credential.id, u64::from(credential.issuer_version), 0, 0]).into(),
        cred_sub_blinding_factor: *credential_sub_blinding_factor,
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        id_commitment_r: *session_id_r_seed,
        id_commitment: Fq::from(0u64), // No session ID for benchmark
        dlog_e: dlog_proof.e(),
        dlog_s: dlog_proof.s(),
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

/// Benchmark: Query Proof (π1) generation from cached input
///
/// This benchmarks `generate_proof` with input and proving material cached after
/// the first call. It still includes witness generation plus Groth16 proving;
/// use `bench_query_proving_only` to measure Groth16 proving from a cached witness.
#[benchmark]
pub fn bench_query_cached_proof_generation() {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_peak_memory_kb: Option<u64>,
}

/// A semantic timing phase captured during a benchmark iteration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct SemanticPhase {
    pub name: String,
    pub duration_ns: u64,
}

/// Resource usage scoped to measured iterations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchResourceUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_total_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_median_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_growth_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_peak_memory_kb: Option<u64>,
}

/// A benchmark harness timeline span.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct HarnessTimelineSpan {
    pub phase: String,
    pub start_offset_ns: u64,
    pub end_offset_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iteration: Option<u32>,
}

/// Benchmark report with timing results
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchReport {
    pub spec: BenchSpec,
    pub samples: Vec<BenchSample>,
    #[serde(default)]
    pub phases: Vec<SemanticPhase>,
    #[serde(default)]
    pub timeline: Vec<HarnessTimelineSpan>,
    #[serde(default)]
    pub resource_usage: Option<BenchResourceUsage>,
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

impl From<mobench_sdk::SemanticPhase> for SemanticPhase {
    fn from(phase: mobench_sdk::SemanticPhase) -> Self {
        Self {
            name: phase.name,
            duration_ns: phase.duration_ns,
        }
    }
}

impl From<mobench_sdk::BenchSample> for BenchSample {
    fn from(sample: mobench_sdk::BenchSample) -> Self {
        Self {
            duration_ns: sample.duration_ns,
            cpu_time_ms: sample.cpu_time_ms,
            peak_memory_kb: sample.peak_memory_kb,
            process_peak_memory_kb: sample.process_peak_memory_kb,
        }
    }
}

impl From<mobench_sdk::HarnessTimelineSpan> for HarnessTimelineSpan {
    fn from(span: mobench_sdk::HarnessTimelineSpan) -> Self {
        Self {
            phase: span.phase,
            start_offset_ns: span.start_offset_ns,
            end_offset_ns: span.end_offset_ns,
            iteration: span.iteration,
        }
    }
}

impl From<mobench_sdk::RunnerReport> for BenchReport {
    fn from(report: mobench_sdk::RunnerReport) -> Self {
        let cpu_total_ms = report.cpu_total_ms();
        let cpu_median_ms = report.cpu_median_ms();
        let peak_memory_kb = report.peak_memory_kb();
        let peak_memory_growth_kb = report.peak_memory_growth_kb();
        let process_peak_memory_kb = report.process_peak_memory_kb();
        let has_resource_usage = cpu_total_ms.is_some()
            || cpu_median_ms.is_some()
            || peak_memory_kb.is_some()
            || peak_memory_growth_kb.is_some()
            || process_peak_memory_kb.is_some();
        let resource_usage = has_resource_usage.then_some(BenchResourceUsage {
            cpu_total_ms,
            cpu_median_ms,
            peak_memory_kb,
            peak_memory_growth_kb,
            process_peak_memory_kb,
        });

        Self {
            spec: BenchSpec {
                name: report.spec.name,
                iterations: report.spec.iterations,
                warmup: report.spec.warmup,
            },
            samples: report.samples.into_iter().map(Into::into).collect(),
            phases: report.phases.into_iter().map(Into::into).collect(),
            timeline: report.timeline.into_iter().map(Into::into).collect(),
            resource_usage,
        }
    }
}

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

    let mut report = BenchReport::from(report);
    report.spec = spec;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[ignore = "expensive benchmark smoke test; run via mobench workflow"]
    fn test_query_proof_benchmark() {
        // Just verify the benchmark runs without panicking
        bench_query_proof_generation();
    }

    #[test]
    #[ignore = "expensive benchmark smoke test; run via mobench workflow"]
    fn test_query_cached_proof_generation_benchmark() {
        // Just verify the benchmark runs without panicking
        bench_query_cached_proof_generation();
    }

    #[test]
    #[ignore = "expensive benchmark smoke test; run via mobench workflow"]
    fn test_nullifier_proof_benchmark() {
        // Just verify the benchmark runs without panicking
        bench_nullifier_proof_generation();
    }

    #[test]
    #[ignore = "expensive benchmark smoke test; run via mobench workflow"]
    fn test_query_witness_only_benchmark() {
        bench_query_witness_generation_only();
    }

    #[test]
    #[ignore = "expensive benchmark smoke test; run via mobench workflow"]
    fn test_query_proving_only_benchmark() {
        bench_query_proving_only();
    }

    #[test]
    #[ignore = "expensive benchmark smoke test; run via mobench workflow"]
    fn test_nullifier_witness_only_benchmark() {
        bench_nullifier_witness_generation_only();
    }

    #[test]
    #[ignore = "expensive benchmark smoke test; run via mobench workflow"]
    fn test_nullifier_proving_only_benchmark() {
        bench_nullifier_proving_only();
    }

    #[test]
    fn test_benchmark_registry_contains_expected_functions() {
        let benchmarks = mobench_sdk::discover_benchmarks();
        let names = benchmarks
            .iter()
            .map(|bench| bench.name.to_string())
            .collect::<Vec<_>>();

        for expected_name in [
            "zk_mobile_bench::bench_query_proof_generation",
            "zk_mobile_bench::bench_query_cached_proof_generation",
            "zk_mobile_bench::bench_query_witness_generation_only",
            "zk_mobile_bench::bench_query_proving_only",
            "zk_mobile_bench::bench_nullifier_proof_generation",
            "zk_mobile_bench::bench_nullifier_witness_generation_only",
            "zk_mobile_bench::bench_nullifier_proving_only",
        ] {
            assert!(
                names.iter().any(|name| name == expected_name),
                "{expected_name} should be registered"
            );
        }
    }

    #[test]
    fn test_run_benchmark_unknown_function_returns_error() {
        let name = "zk_mobile_bench::does_not_exist".to_string();
        let spec = BenchSpec {
            name: name.clone(),
            iterations: 1,
            warmup: 0,
        };

        let err = run_benchmark(spec).expect_err("unknown benchmark should fail");

        assert!(matches!(err, BenchError::UnknownFunction { name: err_name } if err_name == name));
    }

    #[test]
    fn bench_report_json_round_trip_preserves_phases() {
        let expected = json!({
            "spec": {
                "name": "zk_mobile_bench::bench_query_proof_generation",
                "iterations": 1,
                "warmup": 0
            },
            "samples": [
                { "duration_ns": 123 }
            ],
            "phases": [
                { "name": "prove", "duration_ns": 100 },
                { "name": "serialize", "duration_ns": 23 }
            ]
        });

        let report: BenchReport =
            serde_json::from_value(expected.clone()).expect("deserialize benchmark report");
        let actual = serde_json::to_value(report).expect("serialize benchmark report");

        assert_eq!(actual["phases"], expected["phases"]);
    }

    #[test]
    fn bench_report_json_round_trip_preserves_resource_usage() {
        let expected = json!({
            "spec": {
                "name": "zk_mobile_bench::bench_query_proof_generation",
                "iterations": 2,
                "warmup": 0
            },
            "samples": [
                {
                    "duration_ns": 123,
                    "cpu_time_ms": 17,
                    "peak_memory_kb": 4096,
                    "process_peak_memory_kb": 8192
                }
            ],
            "phases": [],
            "timeline": [
                {
                    "phase": "measured-benchmark",
                    "start_offset_ns": 10,
                    "end_offset_ns": 133,
                    "iteration": 0
                }
            ],
            "resource_usage": {
                "cpu_total_ms": 34,
                "cpu_median_ms": 17,
                "peak_memory_kb": 4096,
                "peak_memory_growth_kb": 4096,
                "process_peak_memory_kb": 8192
            }
        });

        let report: BenchReport =
            serde_json::from_value(expected.clone()).expect("deserialize benchmark report");
        let actual = serde_json::to_value(report).expect("serialize benchmark report");

        assert_eq!(actual["samples"], expected["samples"]);
        assert_eq!(actual["timeline"], expected["timeline"]);
        assert_eq!(actual["resource_usage"], expected["resource_usage"]);
    }

    #[test]
    fn sdk_report_conversion_preserves_cpu_total_inputs() {
        let report = mobench_sdk::RunnerReport {
            spec: mobench_sdk::BenchSpec {
                name: "zk_mobile_bench::bench_query_proof_generation".to_string(),
                iterations: 2,
                warmup: 1,
            },
            samples: vec![
                mobench_sdk::BenchSample {
                    duration_ns: 100,
                    cpu_time_ms: Some(11),
                    peak_memory_kb: Some(1024),
                    process_peak_memory_kb: Some(4096),
                },
                mobench_sdk::BenchSample {
                    duration_ns: 200,
                    cpu_time_ms: Some(23),
                    peak_memory_kb: Some(2048),
                    process_peak_memory_kb: Some(8192),
                },
            ],
            phases: vec![mobench_sdk::SemanticPhase {
                name: "prove".to_string(),
                duration_ns: 250,
            }],
            timeline: vec![mobench_sdk::HarnessTimelineSpan {
                phase: "measured-benchmark".to_string(),
                start_offset_ns: 50,
                end_offset_ns: 250,
                iteration: Some(1),
            }],
        };

        let report = BenchReport::from(report);
        let resource_usage = report
            .resource_usage
            .expect("resource usage should be present when CPU samples are present");

        assert_eq!(report.samples[0].cpu_time_ms, Some(11));
        assert_eq!(report.samples[1].cpu_time_ms, Some(23));
        assert_eq!(resource_usage.cpu_total_ms, Some(34));
        assert_eq!(resource_usage.cpu_median_ms, Some(17));
        assert_eq!(resource_usage.peak_memory_kb, Some(2048));
        assert_eq!(resource_usage.peak_memory_growth_kb, Some(2048));
        assert_eq!(resource_usage.process_peak_memory_kb, Some(8192));
        assert_eq!(report.timeline[0].phase, "measured-benchmark");
    }
}
