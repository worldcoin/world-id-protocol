# World ID OPRF Node

The World ID OPRF Node is the protocol's OPRF service implementation. The
workspace package for the service is `world-id-oprf-node`.

## Releases

`world-id-oprf-node` is released independently from the published Rust crates:

1. Review and merge the generated release PR specifically for OPRF Nodes, which updates the package version and [`CHANGELOG.md`](./CHANGELOG.md).
2. After the release PR lands on `main`, the GitHub release will be created, which will trigger the `build-docker.yml` workflow to generate and publish the attested image.
