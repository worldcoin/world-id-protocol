//! Local benchmark runner for testing without mobile devices.
//!
//! Run with: cargo run -p zk-mobile-bench --example run_local --release
//!
//! Pass benchmark names to run a subset, e.g.
//! `cargo run -p zk-mobile-bench --example run_local --release -- bench_deepface_query_proof_generation`

use zk_mobile_bench::{BenchSpec, run_benchmark};

/// Benchmarks run when no names are given on the command line.
const DEFAULT_BENCHMARKS: &[(&str, &str)] = &[
    ("bench_query_proof_generation", "Query Proof pi1"),
    ("bench_nullifier_proof_generation", "Nullifier Proof pi2"),
    (
        "bench_deepface_query_proof_generation",
        "DeepFace Query Proof (cold, ProveKit)",
    ),
    (
        "bench_deepface_query_cached_proof_generation",
        "DeepFace Query Proof (cached prover)",
    ),
];

fn run(name: &str, label: &str, iterations: u32, warmup: u32) {
    println!("Running: {name}");
    println!("  Warmup: {warmup} iteration(s)");
    println!("  Measured: {iterations} iteration(s)");

    let spec = BenchSpec {
        name: format!("zk_mobile_bench::{name}"),
        iterations,
        warmup,
    };

    match run_benchmark(spec) {
        Ok(report) => {
            let durations: Vec<f64> = report
                .samples
                .iter()
                .map(|s| s.duration_ns as f64 / 1_000_000_000.0)
                .collect();

            let mean = durations.iter().sum::<f64>() / durations.len() as f64;
            let min = durations.iter().copied().fold(f64::INFINITY, f64::min);
            let max = durations.iter().copied().fold(f64::NEG_INFINITY, f64::max);

            println!("\n  Results ({label}):");
            println!("    Samples: {durations:?} seconds");
            println!("    Min: {min:.3}s");
            println!("    Max: {max:.3}s");
            println!("    Mean: {mean:.3}s");

            if let Some(usage) = report.resource_usage {
                if let Some(peak) = usage.process_peak_memory_kb {
                    println!("    Process peak RSS: {:.1} MiB", peak as f64 / 1024.0);
                }
                if let Some(growth) = usage.peak_memory_growth_kb {
                    println!("    Peak RSS growth: {:.1} MiB", growth as f64 / 1024.0);
                }
            }
        }
        Err(e) => {
            eprintln!("  Error: {e}");
        }
    }
}

fn main() {
    println!("World ID Mobile Benchmarks - Local Runner");
    println!("==========================================\n");

    let requested: Vec<String> = std::env::args().skip(1).collect();

    let selected: Vec<(&str, &str)> = if requested.is_empty() {
        DEFAULT_BENCHMARKS.to_vec()
    } else {
        requested
            .iter()
            .map(|name| {
                let label = DEFAULT_BENCHMARKS
                    .iter()
                    .find(|(n, _)| n == name)
                    .map_or("custom", |(_, l)| l);
                (name.as_str(), label)
            })
            .collect()
    };

    for (i, (name, label)) in selected.iter().enumerate() {
        if i > 0 {
            println!("\n------------------------------------------\n");
        }
        run(name, label, 3, 1);
    }

    println!("\n==========================================");
    println!("Benchmarks complete!");
}
