SHELL := /bin/bash

.PHONY: help build fmt lint rust-build rust-test rust-fmt rust-clippy run-indexer run-gateway sol-build sol-test sol-fmt test setup-test run-setup run-dev-client

help:
	@echo "Targets:"
	@echo "  build        				- build Rust workspace and Solidity contracts"
	@echo "  fmt          				- format Rust and Solidity code"
	@echo "  lint         				- run Rust clippy (fails on warnings)"
	@echo "  rust-build   				- cargo build --workspace"
	@echo "  rust-test    				- cargo test --workspace"
	@echo "  rust-fmt     				- cargo fmt --all"
	@echo "  rust-clippy  				- cargo clippy --workspace --all-targets -D warnings"
	@echo "  run-indexer  				- run world-id-indexer"
	@echo "  run-gateway  				- run world-id-gateway (PORT 4000 by default)"
	@echo "  sol-build    				- forge build (in contracts/)"
	@echo "  sol-test     				- forge test (in contracts/)"
	@echo "  sol-fmt      				- forge fmt (in contracts/)"
	@echo "  setup-test   				- run local setup and e2e test"
	@echo "  run-setup    				- run local setup"
	@echo "  run-dev-client <command>	- run dev client with <command>"

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
	cargo +nightly fmt --all

rust-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

run-indexer:
	cargo run -p world-id-indexer

run-gateway:
	cargo run -p world-id-gateway

# forge install requires git; skip in Docker where .git is excluded but lib/ contents are copied
sol-build:
	cd contracts && if git rev-parse --git-dir > /dev/null 2>&1; then forge install; fi && forge build && \
	mkdir -p ../crates/authenticator/abi ../crates/issuer/abi ../services/oprf-node/abi && \
	forge inspect WorldIDRegistry abi --json > ../crates/authenticator/abi/WorldIDRegistryAbi.json && \
	forge inspect CredentialSchemaIssuerRegistry abi --json > ../crates/issuer/abi/CredentialSchemaIssuerRegistryAbi.json && \
	forge inspect CredentialSchemaIssuerRegistry abi --json > ../services/oprf-node/abi/CredentialSchemaIssuerRegistryAbi.json && \
	forge inspect RpRegistry abi --json > ../services/oprf-node/abi/RpRegistryAbi.json

sol-test:
	cd contracts && if git rev-parse --git-dir > /dev/null 2>&1; then forge install; fi && forge test -vvv

sol-fmt:
	cd contracts && forge fmt

test:
	$(MAKE) rust-test
	$(MAKE) sol-test
	$(MAKE) setup-test

setup-test:
	./local-setup.sh test
	
run-setup:
	./local-setup.sh setup

# https://stackoverflow.com/questions/2214575/passing-arguments-to-make-run/14061796#14061796
ifeq (run-dev-client,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run-dev-client"
  RUN_DEV_CLIENT_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_DEV_CLIENT_ARGS):;@:)
endif

run-dev-client:
	./local-setup.sh client $(RUN_DEV_CLIENT_ARGS)

