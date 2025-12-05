SHELL := /bin/bash

.PHONY: help build fmt lint rust-build rust-test rust-fmt rust-clippy run-indexer run-gateway sol-build sol-test sol-fmt test

help:
	@echo "Targets:"
	@echo "  build        - build Rust workspace and Solidity contracts"
	@echo "  fmt          - format Rust and Solidity code"
	@echo "  lint         - run Rust clippy (fails on warnings)"
	@echo "  rust-build   - cargo build --workspace"
	@echo "  rust-test    - cargo test --workspace"
	@echo "  rust-fmt     - cargo fmt --all"
	@echo "  rust-clippy  - cargo clippy --workspace --all-targets -D warnings"
	@echo "  run-indexer  - run world-id-indexer"
	@echo "  run-gateway  - run world-id-gateway (PORT 4000 by default)"
	@echo "  sol-build    - forge build (in contracts/)"
	@echo "  sol-test     - forge test (in contracts/)"
	@echo "  sol-fmt      - forge fmt (in contracts/)"

build:
	$(MAKE) sol-build
	$(MAKE) rust-build

fmt:
	$(MAKE) rust-fmt
	$(MAKE) sol-fmt

lint:
	$(MAKE) rust-clippy

rust-build:
	cargo build --workspace -q

rust-test:
	cargo test --workspace -q

rust-fmt:
	cargo fmt --all

rust-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

run-indexer:
	cargo run -p world-id-indexer

run-gateway:
	cargo run -p world-id-gateway

sol-build:
	cd contracts && forge build && \
	forge inspect AccountRegistry abi --json > ../crates/core/contracts/out/AccountRegistry.sol/AccountRegistryAbi.json && \
	forge inspect CredentialSchemaIssuerRegistry abi --json > ../crates/core/contracts/out/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistryAbi.json

sol-test:
	cd contracts && forge test -vvv

sol-fmt:
	cd contracts && forge fmt

test:
	$(MAKE) rust-test
	$(MAKE) sol-test
