####################################################################################################
## Base image
####################################################################################################

FROM rust:1.87-slim AS chef
USER root
WORKDIR /app

RUN apt-get update && apt-get install -y \
  musl-tools \
  clang \
  build-essential \
  pkg-config \
  ca-certificates \
&& rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .

ARG GIT_HASH
ENV GIT_HASH=$GIT_HASH

RUN cargo build --release --locked --target x86_64-unknown-linux-musl
RUN mv target/x86_64-unknown-linux-musl/release/contract-monitor /app/bin

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
