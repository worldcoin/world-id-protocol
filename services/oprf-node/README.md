# World ID OPRF Node

The World ID OPRF Node is the protocol's OPRF service implementation. The
workspace package for the service is `world-id-oprf-node`.

## Releases

`world-id-oprf-node` is released independently from the published Rust crates:

1. Manually trigger the `Prepare OPRF Node Release` workflow (`workflow_dispatch`). It opens a release PR that updates the package version and [`CHANGELOG.md`](./CHANGELOG.md).
2. Review and merge the release PR.
3. On merge, the `Release OPRF Node` workflow detects the version bump, creates the `world-id-oprf-node-vX.Y.Z` tag and GitHub release, and calls `build-docker.yml` to build, attest, and publish the versioned image to GHCR.
