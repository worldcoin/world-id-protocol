# smart contract utilities

set shell := ["bash", "-euo", "pipefail", "-c"]

set positional-arguments

set dotenv-filename := "bridge/contracts/script/.env"

ROOT          := justfile_directory()
CONTRACTS_DIR := ROOT / "contracts"
BRIDGE_DIR    := ROOT / "bridge" / "contracts"
DEPLOY_DIR    := CONTRACTS_DIR / "deployments"
ENV           := env("DEPLOY_ENV", "staging")

# Local dev defaults (overridden by .env or shell env vars)
PRIVATE_KEY   := env("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
WC_PORT       := "18545"
ETH_PORT      := "18546"
WC_RPC        := env("WC_RPC", "http://localhost:" + WC_PORT)
ETH_RPC       := env("ETH_RPC", "http://localhost:" + ETH_PORT)

# Semver from git tags
RELEASE_PREFIX := env('RELEASE_PREFIX', 'world-id-core-')
_TAG           := shell("git tag --list \"${1}v*\" --sort=-v:refname 2>/dev/null | head -1 || true", RELEASE_PREFIX)
VERSION        := if _TAG != "" { trim_start_match(trim_start_match(_TAG, RELEASE_PREFIX), "v") } else { "0.0.0" }

import 'bridge/contracts/Justfile'

import 'justfiles/deploy.just'
import 'justfiles/forge.just'

alias t := test

