# Reproducible build of the OPRF node image on StageX (https://stagex.tools).
#
# StageX is a full-source-bootstrapped musl/LLVM toolchain distributed as
# digest-pinned, multi-maintainer-signed OCI images. Every input below is pinned
# by digest, the build runs offline after `cargo fetch`, and the resulting image
# manifest digest is a function of the git commit. linux/amd64 only.
#
# Build from the repo root (digest must match across independent builders):
#   SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) docker buildx build \
#     --platform linux/amd64 --provenance=false --sbom=false --no-cache \
#     --build-arg GIT_HASH=$(git rev-parse HEAD) \
#     --output type=oci,dest=out,tar=false,rewrite-timestamp=true,force-compression=true,oci-mediatypes=true \
#     -f services/oprf-node/Dockerfile .
#
# StageX release sx2026.09.0 (Rust 1.97.1). Bump all digests together.
FROM docker.io/stagex/pallet-rust:sx2026.09.0@sha256:67f09a98d5b6f7dd99035fc81b2921c2f49f42cd5ac54f63120a3dd1db59b0d4 AS pallet-rust
FROM docker.io/stagex/core-cmake:sx2026.09.0@sha256:75ab41e96e7142fbe667e36f482858ce190d3fe5e2bb29835cf1b153cff74d34 AS core-cmake
FROM docker.io/stagex/core-make:sx2026.09.0@sha256:224e0158be845e591c1ebfedc3bda2495e7b45efff94674f9c5d6d8b08a59918 AS core-make
FROM docker.io/stagex/core-ca-certificates:sx2026.09.0@sha256:fe24a3809eba30972b64ddd8b611a6494bebea7631f805d795cec4241f5a11c6 AS core-ca-certificates

FROM pallet-rust AS toolchain
# cmake for aws-lc-sys, make for tikv-jemalloc-sys (autotools). aws-lc-sys ships
# pregenerated bindings for x86_64-unknown-linux-musl, so no bindgen/perl needed.
COPY --from=core-cmake . /
COPY --from=core-make . /
# The pallet provides clang/lld but only exports CC & co. via /etc/profile
# (login shells). Set them explicitly so cc-rs, cmake and configure agree.
ENV CC=clang CXX=clang++ AR=llvm-ar RANLIB=llvm-ranlib \
    TZ=UTC LC_ALL=C \
    CARGO_HOME=/cargo \
    TARGET=x86_64-unknown-linux-musl
# Pin every value jemalloc's configure would otherwise probe from the build host.
# LG_PAGE=12 is the x86_64 page size (image is amd64 only); LG_VADDR is
# cpuid-detected (48 vs 57 on LA57 hosts); LG_HUGEPAGE is read from /sys.
# GIT_CEILING_DIRECTORIES stops configure from `git describe`-ing anything into
# the allocator's version string (.git is also excluded via .dockerignore).
ENV JEMALLOC_SYS_WITH_LG_PAGE=12 \
    JEMALLOC_SYS_WITH_LG_VADDR=48 \
    JEMALLOC_SYS_WITH_LG_HUGEPAGE=21 \
    GIT_CEILING_DIRECTORIES=/app/target
# StageX's musl target defaults to dynamic linking; crt-static restores fully
# static binaries. build-id=none removes the linker's build-id note.
ENV RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--build-id=none"
# SOURCE_DATE_EPOCH=1 and CARGO_INCREMENTAL=0 are preset by the pallet.

FROM toolchain AS builder
# Embedded via `taceo_nodes_common::version_info!()`; a function of the commit.
ARG GIT_HASH
ENV GIT_HASH=$GIT_HASH
WORKDIR /app
# look at .dockerignore if this does not copy what you want
COPY . .
# Fetch with network, build without. --target is required so RUSTFLAGS do not
# apply to proc-macros and build scripts (crt-static breaks proc-macro dylibs).
RUN cargo fetch --locked --target "${TARGET}"
RUN --network=none cargo build --frozen --locked --profile reproducible \
    --target "${TARGET}" --package world-id-oprf-node --bin world-id-oprf-node
RUN mkdir -p /app/data && touch /app/data/.keep

FROM scratch
WORKDIR /app

COPY --from=core-ca-certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/reproducible/world-id-oprf-node /app/bin
COPY --from=builder --chown=100:100 /app/data /data

USER 100
EXPOSE 8080
CMD ["/app/bin"]
