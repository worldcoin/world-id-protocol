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

## Matrix Used in CI

For each selected platform (iOS / Android), CI can run:

- `proof_scope=pi2`: only the three `pi2` functions.
- `proof_scope=pi1`: only the three `pi1` functions.
- `proof_scope=both`: all six functions.

`modes` controls which parts run:

- `witness`
- `proving`
- `full`
- `all` (default)
