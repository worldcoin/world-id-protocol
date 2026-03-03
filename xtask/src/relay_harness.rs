//! Harness for spawning and managing the relay binary during E2E tests.
//!
//! Generates a TOML config file, spawns the `world-id-relay` binary as a child
//! process, and monitors stdout for the readiness signal.

use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use eyre::{Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::broadcast;
use tracing::info;

/// Configuration used to generate a TOML config file for the relay process.
pub struct RelayHarnessConfig {
    /// Host port of the World Chain anvil (WS).
    pub wc_port: u16,
    /// Host port of the Ethereum anvil (WS).
    pub eth_port: u16,
    /// WorldIDSource proxy address on WC.
    pub source_proxy: Address,
    /// WorldIDRegistry address on WC.
    pub wid_registry: Address,
    /// CredentialSchemaIssuerRegistry address on WC.
    pub issuer_registry: Address,
    /// OprfKeyRegistry address on WC.
    pub oprf_registry: Address,
    /// WorldIDSatellite address on ETH.
    pub eth_satellite: Address,
    /// EthereumMPTGatewayAdapter address on ETH.
    pub eth_gateway: Address,
    /// DisputeGameFactory address on ETH.
    pub dgf: Address,
    /// Hex-encoded private key for the relay signer (no `0x` prefix).
    pub signer_key: String,
    /// Optional destinations JSON path for additional satellites.
    pub destinations_json: Option<PathBuf>,
}

/// A running relay child process with stdout/stderr monitoring.
pub struct RelayProcess {
    child: Child,
    _stdout_task: tokio::task::JoinHandle<()>,
    _stderr_task: tokio::task::JoinHandle<()>,
    log_rx: broadcast::Receiver<String>,
}

impl RelayProcess {
    /// Spawn the relay binary with a generated TOML config.
    pub async fn start(cfg: &RelayHarnessConfig) -> Result<Self> {
        let config_path = write_config(cfg).context("writing relay TOML config")?;
        let relay_bin = find_or_build_relay().await.context("locating relay binary")?;

        info!(bin = %relay_bin.display(), config = %config_path.display(), "spawning relay process");

        let mut child = Command::new(&relay_bin)
            .arg("--config")
            .arg(&config_path)
            .env("NO_COLOR", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("spawning relay process")?;

        let (log_tx, log_rx) = broadcast::channel(256);

        // Monitor stdout.
        let stdout = child.stdout.take().expect("stdout is piped");
        let tx1 = log_tx.clone();
        let _stdout_task = tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::info!(target: "relay.stdout", "{}", line);
                let _ = tx1.send(line);
            }
        });

        // Monitor stderr (tracing typically logs here).
        let stderr = child.stderr.take().expect("stderr is piped");
        let tx2 = log_tx;
        let _stderr_task = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::info!(target: "relay.stderr", "{}", line);
                let _ = tx2.send(line);
            }
        });

        Ok(Self {
            child,
            _stdout_task,
            _stderr_task,
            log_rx,
        })
    }

    /// Block until the relay emits the readiness signal on stdout (30s timeout).
    pub async fn wait_ready(&mut self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    eyre::bail!("relay did not become ready within 30s");
                }
                result = self.log_rx.recv() => {
                    match result {
                        Ok(line) if line.contains("subscribed to ChainCommitted") => {
                            info!("relay process is ready");
                            return Ok(());
                        }
                        Ok(_) => continue,
                        Err(broadcast::error::RecvError::Closed) => {
                            eyre::bail!("relay stdout closed before ready signal");
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
            }
        }
    }

    /// Stop the relay process.
    pub async fn stop(mut self) -> Result<()> {
        self.child.kill().await.context("killing relay process")?;
        info!("relay process stopped");
        Ok(())
    }
}

// ── Config generation ────────────────────────────────────────────────────────

/// Write `xtask.toml` in the workspace root with relay + fuzz configuration.
///
/// The relay reads the top-level `[world_chain]` and `[ethereum_chain]` sections.
/// The fuzzer reads the `[fuzz]` section. Both coexist in one file.
fn write_config(cfg: &RelayHarnessConfig) -> Result<PathBuf> {
    let path = workspace_root().join("xtask.toml");

    let destinations_line = cfg
        .destinations_json
        .as_ref()
        .map(|p| format!("destinations_config = \"{}\"\n", p.display()))
        .unwrap_or_default();

    let toml = format!(
        r#"# Auto-generated by xtask bootstrap. Do not edit.
{destinations_line}commitment_batch_window_secs = 1
batch_interval_secs = 5

[world_chain]
bridge = "{source_proxy}"
oprf_key_registry = "{oprf_registry}"
credential_issuer_schema_registry = "{issuer_registry}"
world_id_registry = "{wid_registry}"

[world_chain.provider]
http = ["http://localhost:{wc_port}"]

[world_chain.provider.signer]
wallet_private_key = "{signer_key}"

[ethereum_chain]
dispute_game_factory = "{dgf}"
game_type = 0
require_finalized = false

[ethereum_chain.base]
bridge = "{eth_satellite}"
gateway = "{eth_gateway}"

[ethereum_chain.base.provider]
http = ["http://localhost:{eth_port}"]

[ethereum_chain.base.provider.signer]
wallet_private_key = "{signer_key}"

[fuzz]
rounds = 10
delay_ms = 500
propagation_timeout_secs = 60
"#,
        destinations_line = destinations_line,
        source_proxy = cfg.source_proxy,
        oprf_registry = cfg.oprf_registry,
        issuer_registry = cfg.issuer_registry,
        wid_registry = cfg.wid_registry,
        wc_port = cfg.wc_port,
        signer_key = cfg.signer_key,
        dgf = cfg.dgf,
        eth_satellite = cfg.eth_satellite,
        eth_gateway = cfg.eth_gateway,
        eth_port = cfg.eth_port,
    );

    std::fs::write(&path, &toml).context("writing relay config TOML")?;
    info!(path = %path.display(), "wrote relay config");

    Ok(path)
}

// ── Binary discovery ─────────────────────────────────────────────────────────

/// Workspace root, derived from the xtask crate's manifest directory.
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("xtask crate must be inside a workspace")
        .to_path_buf()
}

/// Locate a pre-built `world-id-relay` binary or build it on demand.
async fn find_or_build_relay() -> Result<PathBuf> {
    let root = workspace_root();
    let release_bin = root.join("target/release/world-id-relay");
    let debug_bin = root.join("target/debug/world-id-relay");

    if release_bin.exists() {
        info!(path = %release_bin.display(), "found release relay binary");
        return Ok(release_bin);
    }

    if debug_bin.exists() {
        info!(path = %debug_bin.display(), "found debug relay binary");
        return Ok(debug_bin);
    }

    info!("relay binary not found, building with cargo");
    build_relay(&root).await?;

    if debug_bin.exists() {
        return Ok(debug_bin);
    }

    eyre::bail!(
        "relay binary not found at {} or {} after build",
        release_bin.display(),
        debug_bin.display()
    )
}

/// Run `cargo build -p world-id-relay` inside the workspace root.
async fn build_relay(workspace: &Path) -> Result<()> {
    let status = Command::new("cargo")
        .args(["build", "-p", "world-id-relay"])
        .current_dir(workspace)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .context("running cargo build for relay")?;

    if !status.success() {
        eyre::bail!("cargo build -p world-id-relay failed (exit {status})");
    }

    Ok(())
}

