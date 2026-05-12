# World ID OPRF Node

The World ID OPRF Node is the protocol's OPRF service implementation. The
workspace package for the service is `world-id-oprf-node`.

## Releases

`world-id-oprf-node` is released independently from the published Rust crates:

1. Trigger the `Prepare OPRF Node Release` GitHub Actions workflow manually.
2. Review and merge the generated release PR, which updates the package version
   and [`CHANGELOG.md`](./CHANGELOG.md).
3. After the release PR lands on `main`, the `Publish OPRF Node Release`
   workflow detects the version bump in `Cargo.toml`, creates the
   `world-id-oprf-node-vX.Y.Z` tag and GitHub release, and publishes the
   versioned container image while updating the `latest` tag.
