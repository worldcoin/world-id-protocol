//! A local end-to-end harness that drives the real flamingo verifier host.
//!
//! It owns everything except the host: anvil, the contracts, the channel, the funding, the RP,
//! and the closing settlement. The host is started by hand in a second terminal against the env
//! block this writes, because it is a separate binary in a separate workspace.
//!
//! The host does not settle on chain in this version, so no lane mark is ever raised and the
//! closing settlement pays the collector the whole funded amount.

use std::{path::PathBuf, time::Duration};

use alloy::{
    primitives::{Address, B256, U256},
    providers::ext::AnvilApi as _,
    signers::local::PrivateKeySigner,
};
use alloy_node_bindings::{Anvil, AnvilInstance};
use eyre::{Context as _, OptionExt as _, Result, bail, ensure};
use rand::Rng as _;
use reqwest::Url;
use world_id_fee_escrow::{
    Payment,
    typed_data::{ChannelSettings, domain, epoch_end, epoch_of},
};

use crate::{
    chain::{self, Deployment},
    rp::{Outcome, RpService, Transport},
};

/// The RP this harness registers and pays for.
const RP_ID: u64 = 7;
/// One token, in wei.
const ONE_TOKEN: u128 = 1_000_000_000_000_000_000;
/// Fixed mnemonic, so every run deploys to the same addresses and the env block is stable.
const MNEMONIC: &str = "test test test test test test test test test test test junk";
/// Seconds between anvil blocks.
const BLOCK_TIME_SECS: u64 = 1;
/// How long the host caches a capacity read. Short, so a top-up is visible within a run.
const CAPACITY_TTL_MS: u64 = 1_000;
/// How often the harness polls the host's readiness endpoint.
const READY_POLL: Duration = Duration::from_millis(500);

/// Knobs for one harness run.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    /// Units funded before the first batch, and again after the refusal.
    pub units: u64,
    /// Price of one unit, in whole tokens.
    pub price_tokens: u64,
    /// Epoch length in seconds.
    pub epoch_length_secs: u64,
    /// The host's versioned API root, for example `http://127.0.0.1:8000/v1`.
    pub collector_url: Url,
    /// Port anvil listens on.
    pub anvil_port: u16,
    /// How long to wait for the host to report ready.
    pub ready_timeout: Duration,
    /// Where the env block for the host is written.
    pub env_path: PathBuf,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            units: 3,
            price_tokens: 1,
            epoch_length_secs: 3_600,
            collector_url: "http://127.0.0.1:8000/v1"
                .parse()
                .expect("a valid default url"),
            anvil_port: 8545,
            ready_timeout: Duration::from_secs(180),
            env_path: PathBuf::from("target/local-e2e.env"),
        }
    }
}

/// What the run proved.
#[derive(Debug, Clone)]
pub struct HarnessReport {
    /// The opened channel.
    pub channel_id: B256,
    /// Epoch every unit was billed to.
    pub epoch: u64,
    /// Units the host served before the epoch ran out.
    pub admitted_before_refusal: u64,
    /// The class the host refused the over-capacity request with.
    pub refusal_class: String,
    /// Units the refusal proof established, verified against the RP's own key.
    pub proven_units: u64,
    /// Capacity the host reported alongside the proof.
    pub reported_capacity: u64,
    /// Units the host served after the top-up.
    pub admitted_after_top_up: u64,
    /// Tokens funded into the epoch.
    pub funded: U256,
    /// The collector's token balance once the epoch closed.
    pub collector_balance: U256,
    /// The escrow's token balance once the epoch closed.
    pub escrow_balance: U256,
    /// On-chain `settledUnits`. Zero, because the host does not settle.
    pub settled_units: u64,
}

/// Everything the harness deployed, for the env block and the assertions.
struct Fixture {
    /// Kept for the whole run: dropping it kills the node the host is reading.
    anvil: AnvilInstance,
    deployment: Deployment,
    settings: ChannelSettings,
    channel_id: B256,
    epoch: u64,
    collector: Address,
    spend_key: PrivateKeySigner,
    rpc: Url,
}

/// Runs the whole local end-to-end scenario against a flamingo host.
///
/// # Errors
/// Returns an error at the first deviation, with the step that failed named.
#[expect(
    clippy::too_many_lines,
    reason = "a linear scenario script reads better whole"
)]
pub async fn run(cfg: &HarnessConfig) -> Result<HarnessReport> {
    let fixture = deploy(cfg).await?;
    let price = U256::from(cfg.price_tokens) * U256::from(ONE_TOKEN);

    write_env(cfg, &fixture)?;
    wait_for_ready(cfg).await?;

    let rp = RpService::new(
        Transport::flamingo(cfg.collector_url.clone())?,
        fixture.spend_key.clone(),
        domain(fixture.deployment.chain_id, fixture.deployment.escrow),
        fixture.settings.clone(),
    );
    ensure!(
        rp.channel_id() == fixture.channel_id,
        "the RP and the harness disagree on the channel id"
    );

    // ── Spend the funded capacity ───────────────────────────────────────────
    let mut admitted_before_refusal = 0;
    for unit in 1..=cfg.units {
        match rp.one_request().await? {
            Outcome::Admitted(_) => admitted_before_refusal += 1,
            Outcome::Refused(refused) => bail!(
                "unit {unit} of {} was refused as {}: {}",
                cfg.units,
                refused.code,
                refused.message
            ),
        }
    }
    tracing::info!(
        units = admitted_before_refusal,
        "the host served the funded units"
    );

    // ── The next one must be refused, with a proof ──────────────────────────
    let (refusal_class, proven_units, reported_capacity) = match rp.one_request().await? {
        Outcome::Admitted(_) => bail!(
            "the host served {} units against capacity for {}",
            cfg.units + 1,
            cfg.units
        ),
        Outcome::Refused(refused) => {
            ensure!(
                refused.code == "capacity_exhausted",
                "expected capacity_exhausted, got {}: {}",
                refused.code,
                refused.message
            );
            let proven = rp.verify_refusal(fixture.epoch, &refused)?;
            let capacity = refused
                .capacity
                .ok_or_eyre("the capacity refusal named no capacity")?;
            ensure!(
                proven == capacity,
                "the proof accounts for {proven} units but the host claims capacity {capacity}"
            );
            ensure!(
                proven == cfg.units,
                "the proof accounts for {proven} units, expected {}",
                cfg.units
            );
            (refused.code, proven, capacity)
        }
    };
    tracing::info!(class = %refusal_class, proven_units, "refused at capacity, proof verified");

    // ── Fund more; capacity rises in the same block ─────────────────────────
    let top_up = U256::from(cfg.units) * price;
    chain::fund(
        &wallet(&fixture, 1)?,
        fixture.deployment.escrow,
        fixture.channel_id,
        fixture.epoch,
        top_up,
    )
    .await?;
    // The host caches capacity, so wait out its declared staleness bound before asking again.
    tokio::time::sleep(Duration::from_millis(CAPACITY_TTL_MS * 2)).await;

    let admitted_after_top_up = match rp.one_request().await? {
        Outcome::Admitted(_) => 1,
        Outcome::Refused(refused) => bail!(
            "the host still refuses after a top-up: {} {}",
            refused.code,
            refused.message
        ),
    };
    tracing::info!("the host served a unit bought after the refusal");

    // ── Close the epoch ─────────────────────────────────────────────────────
    // The host does not settle, so nothing raised a lane mark and the closing settlement pays
    // the collector everything that was funded.
    let as_deployer = wallet(&fixture, 0)?;
    let ends_at = epoch_end(&fixture.settings, fixture.epoch).ok_or_eyre("epoch end overflowed")?;
    as_deployer.anvil_set_next_block_timestamp(ends_at).await?;
    as_deployer.anvil_mine(Some(1), None).await?;

    let closed: &[Payment] = &[];
    let settlement = chain::settle(
        &as_deployer,
        fixture.deployment.escrow,
        fixture.channel_id,
        fixture.epoch,
        closed,
    )
    .await?;
    ensure!(
        settlement.closed,
        "an empty batch after the epoch ended did not close it"
    );

    let state = chain::epoch_state(
        &as_deployer,
        fixture.deployment.escrow,
        fixture.channel_id,
        fixture.epoch,
    )
    .await?;
    let collector_balance =
        chain::balance_of(&as_deployer, fixture.deployment.token, fixture.collector).await?;
    let escrow_balance = chain::balance_of(
        &as_deployer,
        fixture.deployment.token,
        fixture.deployment.escrow,
    )
    .await?;

    ensure!(
        collector_balance == state.funded,
        "the collector holds {collector_balance} of the {} funded",
        state.funded
    );
    ensure!(
        escrow_balance.is_zero(),
        "the escrow kept {escrow_balance} after the close"
    );

    Ok(HarnessReport {
        channel_id: fixture.channel_id,
        epoch: fixture.epoch,
        admitted_before_refusal,
        refusal_class,
        proven_units,
        reported_capacity,
        admitted_after_top_up,
        funded: state.funded,
        collector_balance,
        escrow_balance,
        settled_units: state.settledUnits,
    })
}

/// Spawns anvil, deploys the contracts, opens a channel, and funds its first epoch.
async fn deploy(cfg: &HarnessConfig) -> Result<Fixture> {
    let anvil = Anvil::new()
        .mnemonic(MNEMONIC)
        .block_time(BLOCK_TIME_SECS)
        .port(cfg.anvil_port)
        .try_spawn()
        .context("anvil must be on PATH and the port free")?;
    let rpc = anvil.endpoint_url();
    tracing::info!(endpoint = %rpc, "anvil up");

    let deployer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let funder: PrivateKeySigner = anvil.keys()[1].clone().into();
    let spend_key: PrivateKeySigner = anvil.keys()[2].clone().into();
    let collector: PrivateKeySigner = anvil.keys()[3].clone().into();

    let as_deployer = chain::wallet_provider(&rpc, &deployer)?;
    let as_funder = chain::wallet_provider(&rpc, &funder)?;

    let deployment = chain::deploy_all(&as_deployer, deployer.address()).await?;
    chain::register_rp(
        &as_deployer,
        deployment.rp_registry,
        RP_ID,
        deployer.address(),
        spend_key.address(),
    )
    .await?;
    tracing::info!(escrow = %deployment.escrow, token = %deployment.token, "contracts deployed");

    let price = U256::from(cfg.price_tokens) * U256::from(ONE_TOKEN);
    let now = chain::block_timestamp(&as_deployer).await?;
    let settings = ChannelSettings {
        rpId: RP_ID,
        spendKey: spend_key.address(),
        collector: collector.address(),
        token: deployment.token,
        pricePerUnit: price,
        epochLength: cfg.epoch_length_secs,
        // Epoch 0 starts now, so the whole run bills to one epoch.
        epochZero: now,
        salt: B256::from(rand::thread_rng().r#gen::<[u8; 32]>()),
    };
    let escrow_domain = domain(deployment.chain_id, deployment.escrow);
    let channel_id = chain::open_channel(
        &as_funder,
        deployment.escrow,
        &settings,
        settings.channel_id(&escrow_domain),
    )
    .await?;
    let epoch = epoch_of(now, &settings).ok_or_eyre("the channel has no epoch at open")?;

    // Both fundings are approved up front, so the top-up mid-run is one transaction.
    let budget = U256::from(2 * cfg.units) * price;
    chain::mint(&as_deployer, deployment.token, funder.address(), budget).await?;
    chain::approve(&as_funder, deployment.token, deployment.escrow, budget).await?;
    chain::fund(
        &as_funder,
        deployment.escrow,
        channel_id,
        epoch,
        U256::from(cfg.units) * price,
    )
    .await?;
    tracing::info!(channel = %channel_id, epoch, units = cfg.units, "channel opened and funded");

    Ok(Fixture {
        anvil,
        deployment,
        settings,
        channel_id,
        epoch,
        collector: collector.address(),
        spend_key,
        rpc,
    })
}

/// A provider signing with anvil's key at `index`.
fn wallet(fixture: &Fixture, index: usize) -> Result<alloy::providers::DynProvider> {
    let key: PrivateKeySigner = fixture
        .anvil_key(index)
        .ok_or_eyre("anvil has no key at that index")?;
    chain::wallet_provider(&fixture.rpc, &key)
}

impl Fixture {
    fn anvil_key(&self, index: usize) -> Option<PrivateKeySigner> {
        self.anvil.keys().get(index).map(|key| key.clone().into())
    }
}

/// Writes the env block the host needs, and prints it.
fn write_env(cfg: &HarnessConfig, fixture: &Fixture) -> Result<()> {
    let port = cfg
        .collector_url
        .port_or_known_default()
        .ok_or_eyre("the collector url names no port")?;
    let block = format!(
        "# Written by `world-id-fee-channel-demo local-e2e`. Source it, then start the host.\n\
         APP_ENV=development\n\
         ENCLAVE_MODE=mock\n\
         PORT={port}\n\
         PAYMENT_REQUIRED=true\n\
         FEE_ESCROW_RPC_URL={rpc}\n\
         FEE_ESCROW_CHAIN_ID={chain_id}\n\
         FEE_ESCROW_ADDRESS={escrow}\n\
         FEE_COLLECTOR_ADDRESS={collector}\n\
         FEE_ESCROW_CAPACITY_TTL_MS={CAPACITY_TTL_MS}\n",
        rpc = fixture.rpc,
        chain_id = fixture.deployment.chain_id,
        escrow = fixture.deployment.escrow,
        collector = fixture.collector,
    );

    if let Some(parent) = cfg.env_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    std::fs::write(&cfg.env_path, &block)
        .with_context(|| format!("cannot write {}", cfg.env_path.display()))?;

    println!("\n{block}");
    let env_path = std::path::absolute(&cfg.env_path).unwrap_or_else(|_| cfg.env_path.clone());
    println!(
        "Start the host in another terminal:\n\n    cd ~/work/flamingo\n    set -a; source \
         {}; set +a\n    cargo run -p flamingo-verifier-host --features mock-enclave\n",
        env_path.display()
    );
    Ok(())
}

/// Polls the host's readiness endpoint until it answers 200.
///
/// Readiness, not liveness: the host reports ready only once it can read the escrow, so a 200
/// here means the chain wiring in the env block is right.
async fn wait_for_ready(cfg: &HarnessConfig) -> Result<()> {
    let ready = cfg.collector_url.join("/ready")?;
    println!("Waiting up to {:?} for {ready} ...", cfg.ready_timeout);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let deadline = tokio::time::Instant::now() + cfg.ready_timeout;

    let mut last = String::from("no response yet");
    while tokio::time::Instant::now() < deadline {
        match http.get(ready.clone()).send().await {
            Ok(response) if response.status().is_success() => {
                println!("Host is ready.\n");
                return Ok(());
            }
            Ok(response) => last = format!("{} from {ready}", response.status()),
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(READY_POLL).await;
    }
    bail!(
        "the host was not ready within {:?}: {last}. Check that it was started with the env \
         block above and that its escrow reads reach anvil.",
        cfg.ready_timeout
    )
}

/// Prints the one-screen summary.
pub fn print_summary(report: &HarnessReport) {
    let rows: [(&str, String); 10] = [
        ("channel", report.channel_id.to_string()),
        ("epoch", report.epoch.to_string()),
        (
            "served before refusal",
            report.admitted_before_refusal.to_string(),
        ),
        ("refusal class", report.refusal_class.clone()),
        (
            "units proven / capacity",
            format!("{} / {}", report.proven_units, report.reported_capacity),
        ),
        (
            "served after top-up",
            report.admitted_after_top_up.to_string(),
        ),
        ("on-chain settled units", report.settled_units.to_string()),
        ("funded", report.funded.to_string()),
        ("collector balance", report.collector_balance.to_string()),
        ("escrow balance", report.escrow_balance.to_string()),
    ];

    println!();
    for (label, value) in rows {
        println!("{label:<26} {value}");
    }
    println!("\nThe host does not settle on chain, so settled units stay zero and the closing");
    println!("settlement paid the collector everything that was funded.");
}
