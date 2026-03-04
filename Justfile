# project utilities

set shell := ["bash", "-euo", "pipefail", "-c"]

set positional-arguments

set export

set dotenv-filename := "contracts/script/crosschain/.env"

ROOT          := justfile_directory()
CONTRACTS_DIR := ROOT / "contracts"
BRIDGE_DIR    := CONTRACTS_DIR
DEPLOY_DIR    := CONTRACTS_DIR / "deployments"
ENV           := env("DEPLOY_ENV", "staging")

# ── Local dev ───────────────────────────────────────────────────────────────
# Default PRIVATE_KEY is Anvil account #0 — safe for local use only.
PRIVATE_KEY   := env_var_or_default("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
WC_PORT       := "18545"
ETH_PORT      := "18546"
WC_RPC        := env_var_or_default("WC_RPC", "http://localhost:" + WC_PORT)
ETH_RPC       := env_var_or_default("ETH_RPC", "http://localhost:" + ETH_PORT)

# ── Production ops ───────────────────────────────────────────────────────────
# WORLDCHAIN_PROVIDER overrides the default public RPC for mainnet/staging ops.
WORLDCHAIN_RPC   := env_var_or_default("WORLDCHAIN_PROVIDER", "https://worldchain-mainnet.g.alchemy.com/public")
WORLDCHAIN_CHAIN := "480"
VERIFIER_URL     := env_var_or_default("VERIFIER_URL", "https://api.etherscan.io/v2/api?chainid=480")

# ── Deployment artifact paths ────────────────────────────────────────────────
CORE_DEPLOY_DIR  := CONTRACTS_DIR / "deployments" / "core"
XC_DEPLOY_DIR    := CONTRACTS_DIR / "deployments" / "crosschain"
XC_CFG_DIR       := CONTRACTS_DIR / "script" / "crosschain" / "config"

# ── Forge script entrypoints ─────────────────────────────────────────────────
CORE_SCRIPT      := "script/core/Deploy.s.sol:Deploy"
XC_SCRIPT        := "script/crosschain/Deploy.s.sol:Deploy"

# ── Parallelism ──────────────────────────────────────────────────────────────
# CPU count for --jobs / --test-threads flags.
PARALLEL_JOBS := num_cpus()

# GNU parallel shebang runner — executes each recipe-body line as a parallel
# `just` invocation. Use as `#! {{ MAP_JUST }}` in a recipe body.
MAP_JUST := "/usr/bin/env -S parallel --shebang --jobs " + PARALLEL_JOBS + " --colsep ' ' -r " + just_executable()

# ── Semver from git tags ─────────────────────────────────────────────────────
RELEASE_PREFIX := env('RELEASE_PREFIX', 'world-id-core-')
_TAG           := shell("git tag --list \"${1}v*\" --sort=-v:refname 2>/dev/null | head -1 || true", RELEASE_PREFIX)
VERSION        := if _TAG != "" { trim_start_match(trim_start_match(_TAG, RELEASE_PREFIX), "v") } else { "0.0.0" }

[doc("On-chain deploy, upgrade, and ops")]
mod contracts 'contracts/Justfile'

import 'just/cargo.just'
import 'just/forge.just'
import 'just/test.just'

[group('ci')]
ci: cargo-lint fmt-check all