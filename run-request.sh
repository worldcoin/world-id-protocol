#!/bin/bash

cargo run -p world-id-core --bin issuer --features cli -- 0 > /tmp/credential.json
cargo run -p world-id-core --bin rp --features cli > /tmp/rp_request.json
RUST_LOG=debug SEED=0101010101010101010101010101010101010101010101010101010101010101 cargo run -p world-id-core --features "authenticator cli" --bin authenticator /tmp/credential.json /tmp/rp_request.json