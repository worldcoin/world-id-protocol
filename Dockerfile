####################################################################################################
## Base image
####################################################################################################
FROM rust:1-slim AS chef
USER root
WORKDIR /app

ARG SERVICE_NAME
RUN test -n "$SERVICE_NAME" || (echo "ERROR: SERVICE_NAME is required" && exit 1)

# Install dependencies for cross-compilation
# TODO: remove perl, make, build-essential, pkg-config once openssl is removed
RUN apt-get update && apt-get install -y \
    musl-tools \
    clang \
    libssl-dev \
    pkg-config \
    build-essential \
    perl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --locked --recipe-path recipe.json --package $SERVICE_NAME
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl --package $SERVICE_NAME
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
