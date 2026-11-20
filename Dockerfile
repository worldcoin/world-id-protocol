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

# Install nargo, which world-id-proof's build script runs to embed Noir circuit verifiers.
# The version and hash match nix/nargo.nix.
ARG NARGO_VERSION=1.0.0-beta.26
ARG NARGO_SHA256=64048040befd55a987158b11137d8f38f9688f696db4d84910dd1bcf0442fb80
RUN curl -fsSL -o /tmp/nargo.tar.gz "https://github.com/noir-lang/noir/releases/download/v${NARGO_VERSION}/nargo-x86_64-unknown-linux-gnu.tar.gz" \
 && echo "${NARGO_SHA256}  /tmp/nargo.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/nargo.tar.gz -C /usr/local/bin nargo \
 && rm /tmp/nargo.tar.gz

RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json --package $SERVICE_NAME
COPY . .

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
