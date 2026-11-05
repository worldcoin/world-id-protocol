# Temporary dependency patches

These patches remove the unmaintained `astral-tokio-tar` (RUSTSEC-2026-0440) and
`pin-utils` (RUSTSEC-2026-0441) crates while awaiting compatible upstream releases.
The source directories come from the published crates.io packages, with registry
metadata and their standalone lockfiles omitted. Upstream license files are retained.
Trailing whitespace in the vendored Testcontainers documentation is normalized.

| Package | Base | Changes | Removal condition |
| --- | --- | --- | --- |
| `testcontainers` | 0.27.3 | Backport the `tar` migration and regression tests from [upstream PR #1006](https://github.com/testcontainers/testcontainers-rs/pull/1006), commit `dba4383d9bdbaed68d499f6e3ba933a289ba0a4a`. Enable `tokio-util/io-util` for the blocking parser bridge. | The workspace and its transitive callers can use a release that removes `astral-tokio-tar`. |
| `semaphore-rs-storage` | 0.6.0 | Change only the `mmap-rs` requirement from 0.6.1 to 0.7, which uses `nix` 0.30 without `pin-utils`. Rust source is unchanged. | Semaphore releases this dependency upgrade. |
| `semaphore-rs-trees` | 0.6.0 | Same `mmap-rs` dependency upgrade; Rust source is unchanged. | Semaphore releases this dependency upgrade. |
| `wasmtimer` | 0.4.3 | Pin [upstream PR #32](https://github.com/whizsid/wasmtimer-rs/pull/32), commit `ec8e518dfd7056b03e309c7776cb1371869c1487`, which replaces `pin-utils` with `pin-project-lite`. This patch uses the upstream Git repository. | A release includes the migration. |

The other `pin-utils` paths are removed by the Hyper and AWS SDK/Smithy updates in
the workspace lockfile. The AWS versions require Rust 1.94.1.

The Testcontainers backport also checks for truncated file payloads after the
streaming copy, with a regression test, so a short archive cannot report success.

Cargo applies these patches to this workspace only; it does not propagate them to
consumers of published workspace crates. Keep the patches until the corresponding
upstream releases can be used directly.

To check the vendored archive migration and storage behavior locally:

```sh
cargo test --manifest-path patches/testcontainers/Cargo.toml --lib core::copy::tests
cargo test --manifest-path patches/testcontainers/Cargo.toml --lib core::client::tests::extract_file_entry
cargo test --manifest-path patches/semaphore-rs-storage/Cargo.toml --lib
cargo test --manifest-path patches/semaphore-rs-trees/Cargo.toml --lib \
  --config 'patch.crates-io.semaphore-rs-storage.path="patches/semaphore-rs-storage"'
```
