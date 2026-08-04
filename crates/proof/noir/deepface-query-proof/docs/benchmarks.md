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
| `deepface_query_proof` (billing tree depth 30) | 26,520 |
| `ownership_proof`, for reference | 26,059 |

The Query Proof costs about the same as the existing WIP-103 ownership proof.

### Cost by billing tree depth

| Billing tree depth | ACIR opcodes |
|---|---|
| 10 | 19,320 |
| 20 | 22,920 |
| 30 | 26,520 |

Exactly linear: **15,720 fixed + 360 per level**. The fixed part is the credential
signature check, the claims-hash opening, the session id commitment and the nonce binding.

Depth 30 is what this package ships, to keep the comparison against the registry-sized
trees honest. It is not what the design needs: the billing tree holds only the humans
enrolled under one `(rp_id, period)` pair, so depth `ceil(log2(n))` suffices. At the Zoom
plugin's 100 World IDs per seat, 100 seats is 10,000 leaves, i.e. depth 14 and **20,760
opcodes -- 22% cheaper than depth 30**. Sizing the tree to the purchased quota is free
performance, and the quota is already known at `purchase()` time.

### Cost of opening a single claim

Publishing `pcp_hash` as one claim slot and recomputing the aggregate `claims_hash`
in-circuit -- rather than publishing the aggregate directly -- costs one Poseidon2 t16
permutation: **868 opcodes**, 3.4% of the circuit. See
[Which credential field `pcp_hash` is](#which-credential-field-pcp_hash-is).

## Proving

One benchmark per process, 1 warmup + 3 measured iterations.

| Benchmark | Mean | Min | Max | Process peak RSS |
|---|---|---|---|---|
| `bench_deepface_query_proof_generation` (cold) | 0.339 s | 0.335 s | 0.346 s | 117 MiB |
| `bench_deepface_query_cached_proof_generation` | 0.234 s | 0.232 s | 0.236 s | 105 MiB |

- *cold* includes fixture generation, deserializing the embedded prover, witness
  generation and proving. It is the path a client hits on its first DeepFace request of a
  billing period.
- *cached* skips fixture setup and prover deserialization, so it is witness generation
  plus proving, and one clone of the prover, which
  `provekit_prover::Prove::prove` requires because it consumes the prover.

Verification is measured by `cargo test --release --test deepface_query_proof`: 9 tests,
each of which proves and verifies once, complete in 0.46 s total.

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
| `deepface_query_proof.pkp` (prover) | 718 KiB |
| `deepface_query_proof.pkv` (verifier) | 419 KiB |
| `OPRFQuery.arks.zkey` + graph, for reference | 11.4 MiB |
| `OPRFNullifier.arks.zkey` + graph, for reference | 26.7 MiB |

The prover is **~38x smaller** than the Circom nullifier material. There is also no
trusted setup: the artifacts are derived from the checked-in Noir source by the ProveKit
R1CS compiler at build time, so there is no ceremony to run and no ceremony output to
distribute or pin.

## Which credential field `pcp_hash` is

The YABS doc names a public `PCP hash` input and says the TEE must check it "matches the
one derived from `hashes.json`", without naming the signed credential field that carries
it. It is **claim slot 0 of the iris (orb signup) credential**, which `signup-service`
already issues.

The PoH credential is not issued in this repo, so the schema has to be read there:
`createClaimFromPcp` in `iris/app-api/handlers/utils.go` sets a single claim to
`base64(hashes.json)`, and `Claims` entries are documented as "raw claim values (base64
encoded)" that "the signer will compute the Poseidon2 hash for", with "indices assigned
automatically (0, 1, 2, ...)". So the base64 is JSON transport, the pre-image is the
`hashes.json` bytes, the value is `H(b"CLAIMS_HASH_V1" || hashes.json)`, and the slot is 0 --
precisely what the enclave can derive from the `hashes.json` it already holds.

Ruled out:

- `associated_data_commitment`. The `Credential` docs make it issuer-private
  ("never exposed to RPs or others") with a structure "solely determined by the issuer", so
  binding the protocol to it would misuse the field *and* let an issuer break this circuit
  by changing its own encoding.
- The aggregate `claims_hash`, because **the TEE cannot check it**: deriving it needs every
  claim slot, and the TEE only ever sees the PCP. Publishing it would also leak a handle to
  claims the TEE has no business learning.

Note `services/faux-issuer` sets no claims, so it says nothing about the real schema -- it
is a stand-in, not the PoH issuer.

Three caveats:

- **Claim indices are schema-scoped.** The *face* credential, from the same service, uses
  slot 0 for a uniqueness flag and slot 1 for a score, written via `ClaimHashes` so they
  land verbatim instead of Poseidon2-hashed. A slot index therefore only means something
  alongside `issuer_schema_id`, which the TEE must pin to the PoH schema. Not directly
  exploitable -- the face credential's slot 0 is the constant `1`, which cannot match a
  `hashes.json` digest -- but the pin is what gives the index meaning.
- **`hashes.json` is version-dependent.** The PCP versions doc specifies it as a flattened,
  entry-sorted JSON of file to sha256, and several PCP versions are in circulation. The
  enclave has to canonicalise identically to the orb for the version it is handed, or the
  claim will not match.
- `Credential::claims_hash` has **no domain separator**: all 16 slots are data, and the
  t16 output is taken at index 1 -- the same permutation and output index as
  `MerkleLeaf` in `circom/client_side_proofs/oprf_query.circom`, which *does* reserve a
  capacity element for one. Iris claim values are domain-separated individually, but the
  face domain writes claim values verbatim, so that mitigation is not universal, and there
  is no spare slot to add a separator without a credential version bump.

## Cost of proving control of the World ID

The circuit deliberately does not prove that the prover controls the `mt_index` it opens
the billing leaf to -- no `WorldIDRegistry` inclusion proof and no authenticator signature.
See the module docs in `src/main.nr`.

Closing that gap in *this* circuit means adding the `ownership_proof` constraints. Since
that circuit measures 26,059 opcodes and the two share only the session id commitment and
the nonce binding, it would add roughly 25,800 -- **about doubling the circuit, to ~52,000
opcodes**, and by the linearity above, proving time with it. That is an estimate from the
two measured circuit sizes, not a measurement of a combined circuit.

Whether to pay it here is a design question. The cheaper alternative is to keep ownership
on the cold path -- enrollment already carries such a proof -- and add a rotation operation
so a compromised session secret can be revoked without re-enrolling.

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
- Peak RSS is the number to watch on device, not time. 105 MiB of process peak on a laptop
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
