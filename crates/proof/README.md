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
noirup --version v1.0.0-beta.11
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
