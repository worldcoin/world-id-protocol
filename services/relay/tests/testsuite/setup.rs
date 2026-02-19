use std::{path::PathBuf, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::{Context, Result, bail};
use serde::Deserialize;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::task::JoinHandle;

use world_id_relay::{
    config::GatewayType,
    relay::{DestinationContext, GatewayContext, RelayContext, run_relay},
    source::run_source,
};

// ── Contract interfaces for test queries ────────────────────────────────────

sol! {
    #[sol(rpc)]
    interface IMockRegistry {
        function setLatestRoot(uint256 root) external;
    }

    #[sol(rpc)]
    interface IMockIssuerRegistry {
        function setPubkey(uint64 id, uint256 x, uint256 y) external;
    }

    #[sol(rpc)]
    interface IMockOprfRegistry {
        function setKey(uint160 id, uint256 x, uint256 y) external;
    }

    #[sol(rpc)]
    interface ISatellite {
        function LATEST_ROOT() external view returns (uint256);

        struct Chain {
            bytes32 head;
            uint64 length;
        }
        function KECCAK_CHAIN() external view returns (Chain memory);

        struct Pubkey {
            uint256 x;
            uint256 y;
        }
        function issuerSchemaIdToPubkeyAndProofId(uint64 schemaId)
            external view returns (Pubkey memory pubKey, bytes32 proofId);
        function oprfKeyIdToPubkeyAndProofId(uint160 oprfKeyId)
            external view returns (Pubkey memory pubKey, bytes32 proofId);
    }
}

// ── Constants ───────────────────────────────────────────────────────────────

/// Anvil account #0 — deployer, relay signer, gateway owner.
const DEPLOYER_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Anvil account #1 — provisioner (separate nonce space from relay).
const PROVISIONER_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Issuer schema ID seeded in mock registries.
pub const TEST_ISSUER_SCHEMA_ID: u64 = 1;
/// OPRF key ID seeded in mock registries.
pub const TEST_OPRF_KEY_ID: u64 = 1;

/// Initial root set by the deploy script.
pub const INITIAL_ROOT: u64 = 1000;
/// Initial issuer pubkey (x, y) set by the deploy script.
pub const INITIAL_ISSUER_PUBKEY: (u64, u64) = (11, 12);
/// Initial OPRF pubkey (x, y) set by the deploy script.
pub const INITIAL_OPRF_PUBKEY: (u64, u64) = (13, 14);

// ── Anvil chain management ──────────────────────────────────────────────────

pub struct ManagedChain {
    pub name: &'static str,
    pub chain_id: u64,
    _container: ContainerAsync<GenericImage>,
    endpoint: String,
    pub provider: DynProvider,
    pub signer: PrivateKeySigner,
}

impl ManagedChain {
    pub async fn spawn(name: &'static str, chain_id: u64) -> Result<Self> {
        let container = GenericImage::new("ghcr.io/foundry-rs/foundry", "latest")
            .with_exposed_port(ContainerPort::Tcp(8545))
            .with_wait_for(WaitFor::message_on_stdout("Listening on"))
            .with_entrypoint("anvil")
            .with_cmd([
                "--host",
                "0.0.0.0",
                "--chain-id",
                &chain_id.to_string(),
                "--accounts",
                "2",
            ])
            .start()
            .await
            .with_context(|| format!("failed to start anvil container for {name}"))?;

        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(8545).await?;
        let endpoint = format!("http://{host}:{port}");

        let signer: PrivateKeySigner = DEPLOYER_KEY.parse()?;
        let wallet = EthereumWallet::from(signer.clone());
        let url: url::Url = endpoint.parse()?;
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url)
            .erased();

        let id = provider.get_chain_id().await?;
        assert_eq!(id, chain_id, "chain id mismatch for {name}");

        Ok(Self {
            name,
            chain_id,
            _container: container,
            endpoint,
            provider,
            signer,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Build a fresh provider with the deployer wallet.
    pub fn deployer_provider(&self) -> Result<DynProvider> {
        let wallet = EthereumWallet::from(self.signer.clone());
        let url: url::Url = self.endpoint.parse()?;
        Ok(ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url)
            .erased())
    }

    /// Build a provider with the provisioner wallet (avoids nonce conflicts).
    pub fn provisioner_provider(&self) -> Result<DynProvider> {
        let signer: PrivateKeySigner = PROVISIONER_KEY.parse()?;
        let wallet = EthereumWallet::from(signer);
        let url: url::Url = self.endpoint.parse()?;
        Ok(ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url)
            .erased())
    }
}

// ── Deployed address structs (parsed from forge script JSON output) ─────────

#[derive(Debug, Clone, Deserialize)]
pub struct SourceAddresses {
    #[serde(rename = "sourceProxy")]
    pub source_proxy: Address,
    pub registry: Address,
    #[serde(rename = "issuerRegistry")]
    pub issuer_registry: Address,
    #[serde(rename = "oprfRegistry")]
    pub oprf_registry: Address,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DestAddresses {
    #[serde(rename = "satelliteProxy")]
    pub satellite_proxy: Address,
    pub gateway: Address,
}

// ── WorldIDTestHarness ──────────────────────────────────────────────────────

pub struct WorldIDTestHarness {
    /// World Chain source anvil.
    pub worldchain: ManagedChain,
    /// Destination chain (permissioned gateway) anvil.
    pub destination: ManagedChain,
    /// Deployed source contract addresses.
    pub source_addrs: SourceAddresses,
    /// Deployed destination contract addresses.
    pub dest_addrs: DestAddresses,
}

/// Handle for a running relay instance (source + relay tokio tasks).
pub struct RelayHandle {
    source_handle: JoinHandle<eyre::Result<()>>,
    relay_handle: JoinHandle<eyre::Result<()>>,
}

impl RelayHandle {
    /// Abort both relay tasks.
    pub fn abort(&self) {
        self.source_handle.abort();
        self.relay_handle.abort();
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.source_handle.abort();
        self.relay_handle.abort();
    }
}

impl WorldIDTestHarness {
    /// Spawn chains and deploy all contracts. Returns a fully configured harness.
    pub async fn setup() -> Result<Self> {
        let worldchain = ManagedChain::spawn("worldchain", 480).await?;
        let destination = ManagedChain::spawn("destination", 8453).await?;

        let fixture_dir = fixture_dir();
        std::fs::create_dir_all(&fixture_dir)?;

        // Clean stale forge artifacts
        let contracts_dir = contracts_dir();
        let _ = std::fs::remove_dir_all(contracts_dir.join("broadcast/E2E_Relay.s.sol"));
        let _ = std::fs::remove_dir_all(contracts_dir.join("cache/E2E_Relay.s.sol"));

        // Phase 1: Deploy source contracts on World Chain
        let source_addrs = deploy_source(&worldchain, &contracts_dir, &fixture_dir).await?;

        // Phase 2: Deploy destination contracts (permissioned)
        let dest_addrs = deploy_destination(
            &destination,
            source_addrs.source_proxy,
            &contracts_dir,
            &fixture_dir,
        )
        .await?;

        Ok(Self {
            worldchain,
            destination,
            source_addrs,
            dest_addrs,
        })
    }

    /// Spawn the relay as in-process tokio tasks (source poller + relay loop).
    pub fn spawn_relay(
        &self,
        propagation_interval: Duration,
        event_poll_interval: Duration,
    ) -> Result<RelayHandle> {
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Source task: calls propagateState() + polls for ChainCommitted events.
        let wc_provider = self.worldchain.deployer_provider()?;
        let source_address = self.source_addrs.source_proxy;
        let source_handle = tokio::spawn(run_source(
            wc_provider,
            source_address,
            vec![TEST_ISSUER_SCHEMA_ID],
            vec![TEST_OPRF_KEY_ID],
            propagation_interval,
            event_poll_interval,
            tx,
        ));

        // Relay task: consumes commitments and relays to destinations.
        let relay_wc_provider = self.worldchain.deployer_provider()?;
        let dest_provider = self.destination.deployer_provider()?;

        let relay_ctx = RelayContext {
            wc_provider: relay_wc_provider,
            wc_source_address: source_address,
            l1_provider: None,
            l1_gateway_address: None,
            l1_satellite_address: None,
            dispute_game_factory: None,
            game_type: 0,
            require_finalized: false,
            dispute_game_poll_interval: Duration::from_secs(60),
            dispute_game_timeout: Duration::from_secs(300),
            destinations: vec![DestinationContext {
                chain_id: self.destination.chain_id,
                provider: dest_provider,
                gateways: vec![GatewayContext {
                    gateway_type: GatewayType::Permissioned,
                    address: self.dest_addrs.gateway,
                }],
            }],
            helios_prover_url: None,
        };

        let relay_handle = tokio::spawn(run_relay(relay_ctx, rx));

        Ok(RelayHandle {
            source_handle,
            relay_handle,
        })
    }

    /// Update mock registries on World Chain (uses provisioner key).
    pub async fn update_registry(&self, root: U256, issuer_x: U256, issuer_y: U256) -> Result<()> {
        let provider = self.worldchain.provisioner_provider()?;

        let registry = IMockRegistry::new(self.source_addrs.registry, &provider);
        registry
            .setLatestRoot(root)
            .send()
            .await?
            .get_receipt()
            .await?;

        let issuer = IMockIssuerRegistry::new(self.source_addrs.issuer_registry, &provider);
        issuer
            .setPubkey(TEST_ISSUER_SCHEMA_ID, issuer_x, issuer_y)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(())
    }

    /// Query the destination satellite's latest root.
    pub async fn query_dest_root(&self) -> Result<U256> {
        let sat = ISatellite::new(self.dest_addrs.satellite_proxy, &self.destination.provider);
        Ok(sat.LATEST_ROOT().call().await?)
    }

    /// Query the destination satellite's issuer pubkey for the test schema ID.
    pub async fn query_dest_issuer_pubkey(&self) -> Result<(U256, U256)> {
        let sat = ISatellite::new(self.dest_addrs.satellite_proxy, &self.destination.provider);
        let result = sat
            .issuerSchemaIdToPubkeyAndProofId(TEST_ISSUER_SCHEMA_ID)
            .call()
            .await?;
        Ok((result.pubKey.x, result.pubKey.y))
    }

    /// Query the destination satellite's OPRF pubkey for the test key ID.
    pub async fn query_dest_oprf_pubkey(&self) -> Result<(U256, U256)> {
        let sat = ISatellite::new(self.dest_addrs.satellite_proxy, &self.destination.provider);
        let result = sat
            .oprfKeyIdToPubkeyAndProofId(U160::from(TEST_OPRF_KEY_ID))
            .call()
            .await?;
        Ok((result.pubKey.x, result.pubKey.y))
    }

    /// Query the destination satellite's keccak chain head.
    pub async fn query_dest_chain_head(&self) -> Result<[u8; 32]> {
        let sat = ISatellite::new(self.dest_addrs.satellite_proxy, &self.destination.provider);
        let chain = sat.KECCAK_CHAIN().call().await?;
        Ok(chain.head.0)
    }

    /// Poll until the destination root matches `expected`, with timeout.
    pub async fn poll_dest_root(&self, expected: U256, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() > deadline {
                let actual = self.query_dest_root().await?;
                bail!("timeout waiting for dest root={expected}, got {actual}");
            }
            if let Ok(root) = self.query_dest_root().await {
                if root == expected {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

// ── Forge script deployment ─────────────────────────────────────────────────

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

fn fixture_dir() -> PathBuf {
    contracts_dir().join("test/crosschain/fixtures/e2e_relay")
}

async fn forge_script(
    contract: &str,
    rpc_url: &str,
    contracts_dir: &PathBuf,
    env_vars: &[(&str, &str)],
) -> Result<()> {
    let key = format!("0x{DEPLOYER_KEY}");

    let mut cmd = tokio::process::Command::new("forge");
    cmd.current_dir(contracts_dir)
        .arg("script")
        .arg(format!("script/crosschain/E2E_Relay.s.sol:{contract}"))
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(&key)
        .arg("--skip-simulation")
        .arg("--slow");

    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    let output = cmd
        .output()
        .await
        .with_context(|| format!("failed to execute forge script {contract}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!("forge script {contract} failed:\nstdout: {stdout}\nstderr: {stderr}");
    }

    Ok(())
}

async fn deploy_source(
    chain: &ManagedChain,
    contracts_dir: &PathBuf,
    fixture_dir: &PathBuf,
) -> Result<SourceAddresses> {
    forge_script("DeploySourceRelayE2E", chain.endpoint(), contracts_dir, &[]).await?;

    let json = std::fs::read_to_string(fixture_dir.join("wc_addrs.json"))
        .context("reading wc_addrs.json")?;
    serde_json::from_str(&json).context("parsing wc_addrs.json")
}

async fn deploy_destination(
    chain: &ManagedChain,
    source_proxy: Address,
    contracts_dir: &PathBuf,
    fixture_dir: &PathBuf,
) -> Result<DestAddresses> {
    forge_script(
        "DeployDestRelayE2E",
        chain.endpoint(),
        contracts_dir,
        &[("WC_SOURCE_PROXY", &format!("{source_proxy}"))],
    )
    .await?;

    let json = std::fs::read_to_string(fixture_dir.join("dest_addrs.json"))
        .context("reading dest_addrs.json")?;
    serde_json::from_str(&json).context("parsing dest_addrs.json")
}
