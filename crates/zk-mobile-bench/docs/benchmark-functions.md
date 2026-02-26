# Benchmark Functions

All benchmark functions are defined in `crates/zk-mobile-bench/src/lib.rs`.

## Nullifier / Uniqueness (`pi2`)

- `zk_mobile_bench::bench_nullifier_witness_generation_only`
  - Measures witness generation only.
- `zk_mobile_bench::bench_nullifier_proving_only`
  - Measures Groth16 proving from cached witness.
- `zk_mobile_bench::bench_nullifier_proof_generation`
  - Measures full path (witness generation + proving).

## Query (`pi1`)

- `zk_mobile_bench::bench_query_witness_generation_only`
  - Measures witness generation only.
- `zk_mobile_bench::bench_query_proving_only`
  - Measures Groth16 proving from cached witness.
- `zk_mobile_bench::bench_query_proof_generation`
  - Measures full path (witness generation + proving).

## CI Benchmark Selection

CI runs all six functions by default. The function list is specified directly in the
caller workflow (`mobile-bench.yml`) via the `functions` input to the reusable workflow.
