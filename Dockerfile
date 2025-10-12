####################################################################################################
## Base image
####################################################################################################
FROM rust:1-slim AS chef
USER root
WORKDIR /app

ARG SERVICE_NAME
RUN test -n "$SERVICE_NAME" || (echo "ERROR: SERVICE_NAME is required" && exit 1)

# Install dependencies for cross-compilation
RUN apt-get update && apt-get install -y \
    musl-tools \
    clang \
    build-essential \
    pkg-config \
    perl \
    curl \
    git \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN curl -L https://foundry.paradigm.xyz | bash \
 && /root/.foundry/bin/foundryup

# Provide a musl-targeted C/C++ toolchain required by crates built with cxx/link-cplusplus (circom-witness)
RUN curl -sSL --retry 5 --retry-delay 3 --connect-timeout 30 --max-time 300 https://musl.cc/x86_64-linux-musl-cross.tgz \
    | tar -xz -C /opt \
 && ln -sf /opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc /usr/local/bin/x86_64-linux-musl-gcc \
 && ln -sf /opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-g++ /usr/local/bin/x86_64-linux-musl-g++ \
 && ln -sf /opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-ar /usr/local/bin/x86_64-linux-musl-ar \
 && ln -sf /opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-ranlib /usr/local/bin/x86_64-linux-musl-ranlib



ENV PATH="/root/.foundry/bin:${PATH}"

RUN rustup target add x86_64-unknown-linux-musl

RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --locked --recipe-path recipe.json --package $SERVICE_NAME
COPY . .

# build the contracts to have the ABIs available
RUN make sol-build

RUN rustup target add x86_64-unknown-linux-musl && \
  cargo build --release --locked --target x86_64-unknown-linux-musl --package $SERVICE_NAME

RUN mv target/x86_64-unknown-linux-musl/release/$SERVICE_NAME /app/bin

####################################################################################################
## Final image
####################################################################################################
FROM scratch
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/bin /app/bin

USER 100
EXPOSE 8000
CMD ["/app/bin"]
