# Benchmark Functions

All benchmark functions are defined in `bench-mobile/src/lib.rs`.

## Nullifier / Uniqueness (`π2`)

- `bench_mobile::bench_nullifier_witness_generation_only`
  - Measures witness generation only.
- `bench_mobile::bench_nullifier_proving_only`
  - Measures Groth16 proving from cached witness.
- `bench_mobile::bench_nullifier_proof_generation`
  - Measures full path (witness generation + proving).

## Query (`π1`)

- `bench_mobile::bench_query_witness_generation_only`
  - Measures witness generation only.
- `bench_mobile::bench_query_proving_only`
  - Measures Groth16 proving from cached witness.
- `bench_mobile::bench_query_proof_generation`
  - Measures full path (witness generation + proving).

## Matrix Used in CI

For each selected platform (iOS / Android), CI can run:

- `proof_scope=pi2`: only the three `π2` functions.
- `proof_scope=pi1`: only the three `π1` functions.
- `proof_scope=both`: all six functions.

`modes` controls which parts run:

- `witness`
- `proving`
- `full`
- `all` (default)
