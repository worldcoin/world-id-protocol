SHELL := /bin/bash

.PHONY: help rust-build rust-test rust-fmt rust-clippy run-indexer run-gateway sol-build sol-test sol-fmt test

help:
	@echo "Targets:"
	@echo "  rust-build   - cargo build --workspace"
	@echo "  rust-test    - cargo test --workspace"
	@echo "  rust-fmt     - cargo fmt --all"
	@echo "  rust-clippy  - cargo clippy --workspace --all-targets -D warnings"
	@echo "  run-indexer  - run authtree-indexer"
	@echo "  run-gateway  - run registry-gateway (PORT 4000 by default)"
	@echo "  sol-build    - forge build (in contracts/)"
	@echo "  sol-test     - forge test (in contracts/)"
	@echo "  sol-fmt      - forge fmt (in contracts/)"

rust-build:
	cargo build --workspace -q

rust-test:
	cargo test --workspace -q

rust-fmt:
	cargo fmt --all

rust-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

run-indexer:
	cargo run -p authtree-indexer

run-gateway:
	cargo run -p registry-gateway

sol-build:
	cd contracts && forge build

sol-test:
	cd contracts && forge test -vvv

sol-fmt:
	cd contracts && forge fmt

test:
	$(MAKE) rust-test
	$(MAKE) sol-test
