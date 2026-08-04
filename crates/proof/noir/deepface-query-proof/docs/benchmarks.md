# DeepFace Query Proof benchmarks

Measurements for the `Query Proof` of the YABS "Updated Design", implemented in Noir and
proved with ProveKit.

All numbers below are reproducible from a clean checkout; see [Reproducing](#reproducing).

## Environment

| | |
|---|---|
| Machine | Apple M4 Max, 14 cores, 36 GiB |
| OS | macOS 26.6 |
| Toolchain | `nargo` 1.0.0-beta.11, ProveKit 0.1.4, `--release` |

Numbers are from a laptop, not a phone. They bound the *shape* of the cost, not the
end-user latency; see [Mobile devices](#mobile-devices) for the real-device path.

## Circuit size

| Circuit | ACIR opcodes |
|---|---|
| `deepface_query_proof` (billing tree depth 30) | 25,652 |
| `ownership_proof`, for reference | 26,059 |

The Query Proof costs about the same as the existing WIP-103 ownership proof.

### Cost by billing tree depth

| Billing tree depth | ACIR opcodes |
|---|---|
| 10 | 18,452 |
| 20 | 22,052 |
| 30 | 25,652 |

Exactly linear: **14,852 fixed + 360 per level**. The fixed part is the credential
signature check, the session id commitment and the nonce binding.

Depth 30 is what this package ships, to keep the comparison against the registry-sized
trees honest. It is not what the design needs: the billing tree holds only the humans
enrolled under one `(rp_id, period)` pair, so depth `ceil(log2(n))` suffices. At the Zoom
plugin's 100 World IDs per seat, 100 seats is 10,000 leaves, i.e. depth 14 and **19,892
opcodes — 22% cheaper than depth 30**. Sizing the tree to the purchased quota is free
performance.

## Proving

One benchmark per process, 1 warmup + 3 measured iterations.

| Benchmark | Mean | Min | Max | Process peak RSS |
|---|---|---|---|---|
| `bench_deepface_query_proof_generation` (cold) | 0.354 s | 0.326 s | 0.406 s | 113 MiB |
| `bench_deepface_query_cached_proof_generation` | 0.235 s | 0.230 s | 0.241 s | 102 MiB |

- *cold* includes fixture generation, deserializing the embedded prover, witness
  generation and proving. It is the path a client hits on its first DeepFace request of a
  billing period.
- *cached* skips fixture setup and prover deserialization, so it is witness generation
  plus proving, and one clone of the prover, which
  `provekit_prover::Prove::prove` requires because it consumes the prover.

Verification is measured by `cargo test --release --test deepface_query_proof`: 7 tests,
each of which proves and verifies once, complete in 0.40 s total.

### Methodology note

Run **one benchmark per process**. Running the cold and cached benchmarks in a single
process inflated both (0.872 s and 1.473 s mean) and pushed max to 1.8 s, because they
share the allocator and the process-wide ProveKit NTT tables. The isolated numbers above
are the ones to quote. `run_local` takes benchmark names as arguments for this reason.

## Artifact size

This is where the Noir/ProveKit choice pays off, and it contradicts the trade-off recorded
in the YABS doc ("needs a Circom circuit which needs a heavyweight artifact to be shipped
with the app").

| Artifact | Size |
|---|---|
| `deepface_query_proof.pkp` (prover) | 558 KiB |
| `deepface_query_proof.pkv` (verifier) | 340 KiB |
| `OPRFQuery.arks.zkey` + graph, for reference | 11.4 MiB |
| `OPRFNullifier.arks.zkey` + graph, for reference | 26.7 MiB |

The prover is **~49x smaller** than the Circom nullifier material. There is also no
trusted setup: the artifacts are derived from the checked-in Noir source by the ProveKit
R1CS compiler at build time, so there is no ceremony to run and no ceremony output to
distribute or pin.

## Cost of proving control of the World ID

The circuit deliberately does not prove that the prover controls the `mt_index` it opens
the billing leaf to — no `WorldIDRegistry` inclusion proof and no authenticator signature.
See the module docs in `src/main.nr`.

Closing that gap means adding exactly the `ownership_proof` circuit's constraints. Since
that circuit measures 26,059 opcodes and the two share only the session id commitment,
adding it roughly **doubles the circuit, to about 50,000 opcodes**, and by the linearity
above, proving time with it. That is an estimate from the two measured circuit sizes, not
a measurement of a combined circuit.

Whether it is worth paying is a design question, not a performance one: without it,
soundness rests on `r` and the credential being secrets only the holder has.

## Mobile devices

Yes, this can be benchmarked on real devices, and the plumbing is in place.

`crates/zk-mobile-bench` drives [mobench](https://github.com/worldcoin/mobile-bench-rs) on
BrowserStack, and the two benchmark functions above are registered there alongside the
existing Circom ones. The prover is loaded from the binary via
`embed-deepface-query-prover`, so nothing has to be fetched at runtime on device.

```sh
cargo-mobench run \
  --target ios \
  --function zk_mobile_bench::bench_deepface_query_proof_generation \
  --iterations 30 --warmup 5 \
  --devices "iPhone 11-13" \
  --crate-path crates/zk-mobile-bench \
  --release --fetch
```

In CI, `/mobench platform=both iterations=30 warmup=5` on a PR, or the `bench` label.
Note that `mobile-bench.yml` lists the benchmark functions explicitly via the `functions`
input, so the two new ones must be added there before CI picks them up.

Two caveats before trusting a device run:

- The existing mobile benchmarks are Circom/Groth16. These two are the first ProveKit
  benchmarks in the crate, so an iOS/Android build of the ProveKit prover has not been
  exercised here.
- Peak RSS is the number to watch on device, not time. 102 MiB of process peak on a laptop
  is comfortable; iOS jetsam limits are far tighter than the headroom that suggests.

## Reproducing

```sh
# Circuit size and unit tests
cd crates/proof/noir/deepface-query-proof
nargo test
nargo info

# Correctness, including negative controls
cargo test -p world-id-proof --release \
  --features embed-deepface-query-prover,embed-deepface-query-verifier \
  --test deepface_query_proof

# Proving, one benchmark per process
cargo run -p zk-mobile-bench --example run_local --release -- \
  bench_deepface_query_proof_generation
cargo run -p zk-mobile-bench --example run_local --release -- \
  bench_deepface_query_cached_proof_generation
```

`nargo` must be exactly 1.0.0-beta.11 (`nix develop`, or
`noirup --version v1.0.0-beta.11`); `crates/proof/build.rs` fails the build otherwise.
