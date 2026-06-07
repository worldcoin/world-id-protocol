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

### Publishing circuit artifact releases

Releases are created manually via the `Release circuit artifacts` GitHub Actions workflow, with a
tag like `circuit-artifacts-v0.1.0`. The workflow creates a GitHub release and attaches the
Circom artifact files listed above.

## Noir ownership proof

The Noir ownership proof circuit is compiled just-in-time by `build.rs` using `nargo` and the
provekit R1CS compiler. Building this crate with the `zk-ownership-prove` or `zk-ownership-verify`
features requires `nargo` v1.0.0-beta.11 to be installed:

```sh
noirup --version v1.0.0-beta.11
```
