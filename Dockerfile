####################################################################################################
## Base image
####################################################################################################

# We use the musl-cross image to have a musl-targeted C/C++ toolchain required by crates built with cxx/link-cplusplus (circom-witness)
FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS chef
USER root
WORKDIR /app

ARG SERVICE_NAME
RUN test -n "$SERVICE_NAME" || (echo "ERROR: SERVICE_NAME is required" && exit 1)

# Install dependencies (required for ring crate)
RUN apt-get update && apt-get install -y \
  musl-tools \
  clang \
  build-essential \
  pkg-config \
  ca-certificates \
&& rm -rf /var/lib/apt/lists/*   

# Set RUSTUP_TMP to avoid "Invalid cross-device link" errors in Docker
# This ensures rustup's temp directory is on the same filesystem as RUSTUP_HOME
ENV RUSTUP_TMP=/root/.rustup/tmp

# Remove the pre-installed toolchain and add the MUSL target
COPY rust-toolchain.toml .

RUN mkdir -p $RUSTUP_TMP \
   && rustup set profile minimal \
   && rustup show \
   && rustup target add x86_64-unknown-linux-musl

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash \
 && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json --package $SERVICE_NAME
COPY . .

# Contract ABI JSON files (crates/*/abi/*.json) are committed to the repository and
# are already present after COPY above. Running `make sol-build` here is unnecessary
# for a --release build: world-id-test-utils (the only crate whose build.rs invokes
# forge) is a [dev-dependencies] entry and is never compiled in release mode.
# Removing this step prevents every source-code change from busting the forge layer.

ARG GIT_HASH
ENV GIT_HASH=$GIT_HASH

RUN cargo build --release --locked --target x86_64-unknown-linux-musl --package $SERVICE_NAME

RUN mv target/x86_64-unknown-linux-musl/release/$SERVICE_NAME /app/bin

RUN mkdir -p /app/data && touch /app/data/.keep

####################################################################################################
## Final image
####################################################################################################
FROM scratch
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/bin /app/bin
COPY --from=builder --chown=100:100 /app/data /data

USER 100
EXPOSE 8080
CMD ["/app/bin"]
