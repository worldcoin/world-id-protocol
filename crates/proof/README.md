# World ID Proof

World ID is an anonymous proof of human for the age of AI.

This crate provides the functionality for World ID Proofs.

More information can be found in the [World ID Developer Documentation](https://docs.world.org/world-id).

### Features

##### `embed-zkeys`

build.rs will download zkey files from github and include them into the binary.

Download from github is done as a workaround to circumvent the max crates.io hosting limit.

##### `compress-zkeys` (implies `embed-zkeys`)

build.rs will download and compress zkey files from github and include them into the binary.
At runtime, zkeys are decompressed in memory during initialization.

##### neither `compress-zkeys` or `embed-zkeys`

zkey files are not included in the bin.

## Circuit artifacts

Proof builds do not compile circuits. Instead, `build.rs` resolves prebuilt circuit artifacts by:

1. using files committed in this repository; or
2. downloading them from the GitHub release tag pinned in `build.rs`.

The release tag is intentionally separate from the crate/software version track, e.g.
`circuit-artifacts-v0.1.0`.

### Circom artifacts

The embedded zkey flow uses these artifacts:

- `circom/OPRFQueryGraph.bin`
- `circom/OPRFNullifierGraph.bin`
- `circom/OPRFQuery.arks.zkey`
- `circom/OPRFNullifier.arks.zkey`

When local files are unavailable, they are downloaded from the pinned circuit artifact release.

### Noir ownership proof artifacts

The Noir ownership proof uses persisted provekit artifacts:

- `crates/proof/noir/ownership-proof/artifacts/ownership_proof.pkp`
- `crates/proof/noir/ownership-proof/artifacts/ownership_proof.pkv`

Normal builds only copy/download these files; they do not require `nargo`.

To regenerate them locally:

```sh
just build-noir-artifacts
```

This requires the matching Noir toolchain (`nargo` v1.0.0-beta.11).

### Publishing circuit artifact releases

Circuit artifact releases are created manually with the GitHub Actions workflow:

```text
Release circuit artifacts
```

Run it with a tag like:

```text
circuit-artifacts-v0.1.0
```

The workflow creates a GitHub release and attaches only the circuit artifact files listed above.
