# smart contract utilities

set shell := ["bash", "-euo", "pipefail", "-c"]

set positional-arguments

set dotenv-filename := "contracts/script/.env"

ROOT          := justfile_directory()
CONTRACTS_DIR := ROOT / "contracts"
BRIDGE_DIR    := CONTRACTS_DIR
DEPLOY_DIR    := CONTRACTS_DIR / "deployments"
ENV           := env("DEPLOY_ENV", "local")

# Local dev defaults (overridden by .env or shell env vars)

# Mnemonic:          test test test test test test test test test test test junk
# Derivation path:   m/44'/60'/0'/0/

SIGNER_0 := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
SIGNER_1 := "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
SIGNER_2 := "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
SIGNER_3 := "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
SIGNER_4 := "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
SIGNER_5 := "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
SIGNER_6 := "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"
SIGNER_7 := "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
SIGNER_8 := "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"
SIGNER_9 := "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"

PRIVATE_KEY   := env("PRIVATE_KEY", SIGNER_0)

WC_PORT       := "0"
ETH_PORT      := "0"
WC_RPC        := env("WC_RPC", "http://localhost:" + WC_PORT)
ETH_RPC       := env("ETH_RPC", "http://localhost:" + ETH_PORT)

# Semver from git tags
RELEASE_PREFIX := env('RELEASE_PREFIX', 'world-id-core-')
_TAG           := shell("git tag --list \"${1}v*\" --sort=-v:refname 2>/dev/null | head -1 || true", RELEASE_PREFIX)
VERSION        := if _TAG != "" { trim_start_match(trim_start_match(_TAG, RELEASE_PREFIX), "v") } else { "0.0.0" }

import 'contracts/Justfile'

import 'justfiles/bootstrap.just'
import 'justfiles/deploy.just'
import 'justfiles/forge.just'

alias t := test

# Run the relay E2E integration test (3 anvils + relay binary).
[group('test')]
relay-it:
    just -f services/relay/it.just it

# Manual cleanup for relay E2E test.
[group('test')]
relay-it-stop:
    just -f services/relay/it.just stop

