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

##### `embed-noir-artifacts`

build.rs will download Noir ownership proof artifacts from GitHub and include them into the binary.

##### `build-noir-artifacts` (implies `embed-noir-artifacts`)

build.rs will build Noir ownership proof artifacts ad-hoc with `nargo` and include them into the binary.

##### neither `compress-zkeys` or `embed-zkeys`

zkey files are not included in the bin.

## Circom circuit artifacts

For the embedded zkey flow, `build.rs` resolves prebuilt Circom artifacts by:

1. using files committed in this repository; or
2. downloading them from the GitHub release tag pinned in `build.rs`.

The release tag is intentionally separate from the crate/software version track, e.g.
`circuit-artifacts-v0.1.0`. Artifacts published under that tag:

- `circom/OPRFQueryGraph.bin`
- `circom/OPRFNullifierGraph.bin`
- `circom/OPRFQuery.arks.zkey`
- `circom/OPRFNullifier.arks.zkey`
- `ownership_proof.pkp`
- `ownership_proof.pkv`

### Publishing circuit artifact releases

Releases are created manually via the `Release circuit artifacts` GitHub Actions workflow, with a
tag like `circuit-artifacts-v0.1.0`. The workflow creates a GitHub release and attaches the
Circom and Noir artifact files listed above.

## Noir ownership proof

The Noir ownership proof APIs are available on native targets. They can either use explicit
prover/verifier material loaded from readers or paths, or embedded artifacts when
`embed-noir-artifacts` is enabled.

With `embed-noir-artifacts`, `build.rs` downloads these files from the pinned GitHub artifact
release. CI/release tooling may override the pinned tag with the
`WORLD_ID_CIRCUIT_ARTIFACT_RELEASE_TAG` environment variable:

- `ownership_proof.pkp`
- `ownership_proof.pkv`

With `build-noir-artifacts`, `build.rs` builds those artifacts ad-hoc using `nargo` and the
provekit R1CS compiler. This requires `nargo` v1.0.0-beta.11:

```sh
noirup --version v1.0.0-beta.11
```
