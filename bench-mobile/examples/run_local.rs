//! Local benchmark runner for testing without mobile devices.
//!
//! Run with: cargo run -p world-id-mobile-bench --example run_local --release

use bench_mobile::{run_benchmark, BenchSpec};

fn main() {
    println!("World ID Mobile Benchmarks - Local Runner");
    println!("==========================================\n");

    // Run Query Proof benchmark
    println!("Running: bench_query_proof_generation");
    println!("  Warmup: 1 iteration");
    println!("  Measured: 3 iterations");

    let spec = BenchSpec {
        name: "bench_mobile::bench_query_proof_generation".to_string(),
        iterations: 3,
        warmup: 1,
    };

    match run_benchmark(spec) {
        Ok(report) => {
            let durations: Vec<f64> = report
                .samples
                .iter()
                .map(|s| s.duration_ns as f64 / 1_000_000_000.0)
                .collect();

            let mean = durations.iter().sum::<f64>() / durations.len() as f64;
            let min = durations.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = durations.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

            println!("\n  Results (Query Proof π1):");
            println!("    Samples: {:?} seconds", durations);
            println!("    Min: {:.3}s", min);
            println!("    Max: {:.3}s", max);
            println!("    Mean: {:.3}s", mean);
        }
        Err(e) => {
            eprintln!("  Error: {}", e);
        }
    }

    println!("\n------------------------------------------\n");

    // Run Nullifier Proof benchmark
    println!("Running: bench_nullifier_proof_generation");
    println!("  Warmup: 1 iteration");
    println!("  Measured: 3 iterations");

    let spec = BenchSpec {
        name: "bench_mobile::bench_nullifier_proof_generation".to_string(),
        iterations: 3,
        warmup: 1,
    };

    match run_benchmark(spec) {
        Ok(report) => {
            let durations: Vec<f64> = report
                .samples
                .iter()
                .map(|s| s.duration_ns as f64 / 1_000_000_000.0)
                .collect();

            let mean = durations.iter().sum::<f64>() / durations.len() as f64;
            let min = durations.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = durations.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

            println!("\n  Results (Nullifier Proof π2):");
            println!("    Samples: {:?} seconds", durations);
            println!("    Min: {:.3}s", min);
            println!("    Max: {:.3}s", max);
            println!("    Mean: {:.3}s", mean);
        }
        Err(e) => {
            eprintln!("  Error: {}", e);
        }
    }

    println!("\n==========================================");
    println!("Benchmarks complete!");
}
