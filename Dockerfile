####################################################################################################
## Base image
####################################################################################################

# We use the musl-cross image to have a musl-targeted C/C++ toolchain required by crates built with cxx/link-cplusplus (circom-witness)
FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS chef
USER root
WORKDIR /app

ARG SERVICE_NAME
RUN test -n "$SERVICE_NAME" || (echo "ERROR: SERVICE_NAME is required" && exit 1)

ENV CC_x86_64_unknown_linux_musl=musl-gcc \
  AR_x86_64_unknown_linux_musl=ar

RUN apt-get update && apt-get install -y \
  musl-tools \
  clang \
  build-essential \
  pkg-config \
  perl \
  ca-certificates \
&& rm -rf /var/lib/apt/lists/*   

# Remove the pre-installed toolchain and add the MUSL target
RUN rustup set profile minimal \
 && rustup toolchain uninstall stable || true \
 && rustup toolchain install stable --profile minimal \
 && rustup default stable \
 && rustup target add x86_64-unknown-linux-musl

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash \
 && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

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
