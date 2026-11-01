# World ID Proof

World ID is an anonymous proof of human for the age of AI.

This crate provides the functionality for World ID Proofs.

More information can be found in the [World ID Developer Documentation](https://docs.world.org/world-id).

## Artifact provenance

Each ZK artifact type has exactly one way of being obtained:

- **Circom artifacts** (zkeys, witness graphs) are trusted-setup outputs and cannot be
  rebuilt. `build.rs` uses files committed in this repository when present (development),
  and otherwise downloads them from the GitHub release tag pinned in `build.rs`.
  Material loaders verify them against SHA-256 fingerprints pinned in `src/oprf_query.rs`
  (query proof) and `src/nullifier_proof.rs` (nullifier proof).
- **Noir ownership proof artifacts** (`ownership_proof.pkp` / `.pkv`) are always built
  ad-hoc by `build.rs` from the checked-in circuit source using `nargo`. The required
  `nargo` version is pinned (see `flake.nix` and `REQUIRED_NARGO_VERSION` in `build.rs`); the build
  fails if a different version is on PATH, since a version mismatch can produce keys
  incompatible with everyone else's.

### Features

By default **nothing is embedded**: ZK artifacts are provided at runtime through a
`ZkArtifactSource` (embedded, filesystem, or a client-provided implementation).
Embedding artifacts into the binary is an explicit opt-in per artifact:

##### `embed-zkeys`

build.rs will include the Circom zkey files (query + nullifier proof material) into the
binary (committed files when building in-repo, otherwise downloaded from the pinned GitHub
release).

Download from github is done as a workaround to circumvent the max crates.io hosting limit.

##### `compress-zkeys` (implies `embed-zkeys`)

build.rs will additionally compress the zkey files before embedding them.
At runtime, zkeys are decompressed in memory during initialization.

##### `embed-ownership-prover` / `embed-ownership-verifier`

build.rs will build the Noir ownership proof artifacts with `nargo` and embed the selected
one(s) into the binary. The prover is multi-MB; verifying-only consumers should enable just
the verifier. Requires `nargo` on PATH at the pinned version — use `nix develop` or:

```sh
noirup --version v1.0.0-beta.26
```

##### Umbrellas

- `embed-noir-artifacts` = ownership prover + verifier
- `embed-zk-artifacts` = everything

## Circom circuit artifacts

The release tag is intentionally separate from the crate/software version track, e.g.
`circuit-artifacts-v0.1.0`. Artifacts published under that tag:

- `circom/OPRFQueryGraph.bin`
- `circom/OPRFNullifierGraph.bin`
- `circom/OPRFQuery.arks.zkey`
- `circom/OPRFNullifier.arks.zkey`

Material loaders verify artifacts against the SHA-256 fingerprints pinned in
`src/oprf_query.rs` and `src/nullifier_proof.rs`.

### Publishing circuit artifact releases

Releases are created manually via the `Release circuit artifacts` GitHub Actions workflow,
with a tag like `circuit-artifacts-v0.1.0`. The workflow creates a GitHub release and
attaches the Circom artifact files listed above (committed in this repository). When
publishing a new tag, update both the pinned tag in `build.rs` and the pinned SHA-256
fingerprints in `src/oprf_query.rs` and `src/nullifier_proof.rs`.

## Noir ownership proof

The Noir ownership proof APIs are available on native targets. They can either use explicit
prover/verifier material loaded from readers or paths, or embedded artifacts when the
corresponding `embed-ownership-prover` / `embed-ownership-verifier` feature is enabled.

### ProveKit 1.0.3 migration

[ProveKit 1.0.3](https://github.com/worldfnd/provekit/releases/tag/v1.0.3) records the declared
public-input count in R1CS and enforces it during verification. The ownership circuit has five
public inputs, so both `ownership_proof.pkp` and `ownership_proof.pkv` must be regenerated
together with the pinned ProveKit 1.0.3 compiler. The Noir source and pinned `nargo` version
remain unchanged.

Clear previous package build outputs first to avoid selecting stale keys left by older builds
with a different feature set. Then build with both ownership embed features to regenerate the
pair from the checked-in source:

```sh
cargo clean -p world-id-proof
cargo build --locked -p world-id-proof --features embed-noir-artifacts
cargo test --locked -p world-id-proof --features embed-noir-artifacts ownership_proof
```

The generated files are in `target/debug/build/world-id-proof-*/out/` (or the corresponding
release directory when using `--release`); they are build outputs, not checked-in artifacts.
Embedded consumers receive the regenerated keys when rebuilt. Consumers loading artifacts
from files or a custom `ZkArtifactSource` must replace both keys and generate new proofs with
the new prover. Deploy the matching verifier key with those proofs: v1.0.2 ownership keys are
rejected by v1.0.3, and old proofs cannot be reused with the new keys. Keep the previous
version's keys and proofs available for the coordinated rollout.
