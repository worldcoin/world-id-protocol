//! Bootstrap a full test environment: genesis allocs, anvils, relay.
//!
//! All contract deployment happens in forge scripts via `just gen-allocs`
//! (OP bedrock predeploy pattern). This module only orchestrates:
//! testcontainers, JSON parsing, relay process, and alloy providers.

use std::path::PathBuf;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use eyre::{Context, Result};
use tracing::info;

use crate::{anvil::AnvilContainer, relay_harness};

// ---------------------------------------------------------------------------
// Constants — must match E2E_Bootstrap.s.sol predeploy addresses
// ---------------------------------------------------------------------------

const WC_CHAIN_ID: u64 = 480;
const ETH_CHAIN_ID: u64 = 1;

/// Anvil account #0 private key — used by the relay binary.
pub const RELAY_SIGNER_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Anvil account #1 private key — used by the fuzz loop to avoid nonce conflicts with the relay.
pub const FUZZ_SIGNER_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

// WC predeploys
pub const WC_OPRF_REGISTRY: Address = address!("0x000000000000000000000000000000000000B001");
pub const WC_REGISTRY: Address = address!("0x000000000000000000000000000000000000B002");
pub const WC_ISSUER_REGISTRY: Address = address!("0x000000000000000000000000000000000000B003");
pub const WC_SOURCE: Address = address!("0x000000000000000000000000000000000000B004");

// ETH predeploys
pub const ETH_SATELLITE: Address = address!("0x000000000000000000000000000000000000C001");
pub const ETH_GATEWAY: Address = address!("0x000000000000000000000000000000000000C002");
pub const ETH_DGF: Address = address!("0x000000000000000000000000000000000000C003");
pub const ETH_GAME: Address = address!("0x000000000000000000000000000000000000C004");

// ---------------------------------------------------------------------------
// TestEnvironment
// ---------------------------------------------------------------------------

/// A fully-booted test environment with live anvils, deployed contracts, and relay.
pub struct TestEnvironment {
    pub wc: AnvilContainer,
    pub eth: AnvilContainer,
    pub wc_provider: DynProvider,
    pub eth_provider: DynProvider,
    pub relay: relay_harness::RelayProcess,
}

impl TestEnvironment {
    /// Bootstrap the full environment.
    ///
    /// 1. Generate genesis allocs via `just gen-allocs`
    /// 2. Start WC anvil (with genesis) + ETH anvil (with genesis)
    /// 3. Start relay process
    pub async fn bootstrap() -> Result<Self> {
        // ── Phase 1: Generate genesis allocs ─────────────────────────────
        info!("phase 1: generating genesis allocs");
        run_just(&["gen-allocs"])
            .await
            .context("just gen-allocs failed")?;

        let wc_genesis = wrap_alloc("wc_genesis.json").context("loading WC genesis")?;
        let eth_genesis = wrap_alloc("eth_genesis.json").context("loading ETH genesis")?;

        info!(
            wc_bytes = wc_genesis.len(),
            eth_bytes = eth_genesis.len(),
            "genesis allocs generated"
        );

        // ── Phase 2: Start anvils ────────────────────────────────────────
        info!("phase 2: starting anvil containers");

        let wc = AnvilContainer::start("wc", WC_CHAIN_ID, Some(&wc_genesis))
            .await
            .context("failed to start WC anvil")?;

        let eth = AnvilContainer::start("eth", ETH_CHAIN_ID, Some(&eth_genesis))
            .await
            .context("failed to start ETH anvil")?;

        info!(wc_port = wc.host_port, eth_port = eth.host_port, "anvils running");

        // ── Phase 3: Start relay ─────────────────────────────────────────
        info!("phase 3: starting relay process");

        let mut relay = relay_harness::RelayProcess::start(&relay_harness::RelayHarnessConfig {
            wc_port: wc.host_port,
            eth_port: eth.host_port,
            source_proxy: WC_SOURCE,
            wid_registry: WC_REGISTRY,
            issuer_registry: WC_ISSUER_REGISTRY,
            oprf_registry: WC_OPRF_REGISTRY,
            eth_satellite: ETH_SATELLITE,
            eth_gateway: ETH_GATEWAY,
            dgf: ETH_DGF,
            signer_key: RELAY_SIGNER_KEY.to_string(),
            destinations_json: None,
        })
        .await
        .context("failed to start relay")?;

        relay
            .wait_ready()
            .await
            .context("relay did not become ready")?;

        info!("relay is ready");

        // ── Build providers ──────────────────────────────────────────────
        let signer: PrivateKeySigner = FUZZ_SIGNER_KEY.parse().context("parse signer")?;
        let wallet = EthereumWallet::from(signer);

        let wc_provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .connect_http(wc.rpc_url().parse().context("parse WC RPC URL")?)
            .erased();

        let eth_provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(eth.rpc_url().parse().context("parse ETH RPC URL")?)
            .erased();

        Ok(Self {
            wc,
            eth,
            wc_provider,
            eth_provider,
            relay,
        })
    }

    /// Graceful shutdown.
    pub async fn shutdown(self) -> Result<()> {
        self.relay.stop().await.context("stopping relay")?;
        info!("environment shut down");
        Ok(())
    }
}

/// `just bootstrap` CLI entry point: boot environment, block on Ctrl+C.
pub async fn run() -> Result<()> {
    let env = TestEnvironment::bootstrap().await?;

    info!(
        wc_rpc = %env.wc.rpc_url(),
        eth_rpc = %env.eth.rpc_url(),
        "environment ready — press Ctrl+C to shut down"
    );

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl+C")?;

    info!("shutting down...");
    env.shutdown().await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be inside a workspace")
        .to_path_buf()
}

fn fixture_dir() -> PathBuf {
    workspace_root().join("contracts/test/crosschain/fixtures/e2e_relay")
}

/// Read a `vm.dumpState` JSON file and wrap it as `{"alloc": ...}` for `anvil --init`.
fn wrap_alloc(name: &str) -> Result<Vec<u8>> {
    let path = fixture_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;

    // vm.dumpState produces { "0xaddr": { ... }, ... }
    // anvil --init expects  { "alloc": { "0xaddr": { ... }, ... } }
    let allocs: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

    let genesis = serde_json::json!({ "alloc": allocs });
    serde_json::to_vec(&genesis).context("serializing genesis")
}

async fn run_just(args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new("just")
        .args(args)
        .current_dir(workspace_root())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("running just {}", args.join(" ")))?;

    if !status.success() {
        eyre::bail!("just {} failed (exit {})", args.join(" "), status);
    }
    Ok(())
}
