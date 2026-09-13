//! The whole scenario, shared by the demo binary and the integration test.

use std::time::Duration;

use crate::{
    chain::{self, ChainSnapshot},
    collector::{self, Stats},
    rp::{self, Outcome},
};
use alloy::{
    primitives::{B256, U256},
    providers::ext::AnvilApi as _,
    signers::local::PrivateKeySigner,
};
use alloy_node_bindings::Anvil;
use eyre::{OptionExt as _, Result, bail};
use rand::Rng as _;
use world_id_fee_escrow::{
    LedgerConfig,
    typed_data::{ChannelSettings, domain, epoch_end, epoch_of},
};

/// The RP this demo registers and pays for.
const RP_ID: u64 = 7;
/// One token, in wei.
const ONE_TOKEN: u128 = 1_000_000_000_000_000_000;

/// Knobs for one run of the demo.
#[derive(Debug, Clone, Copy)]
pub struct FlowConfig {
    /// Units funded before the first batch of requests.
    pub first_funding_units: u64,
    /// Units funded after the epoch runs out.
    pub top_up_units: u64,
    /// Units funded and deliberately never spent, to exercise the closing settlement.
    pub unspent_units: u64,
    /// Price of one unit, in whole tokens.
    pub price_tokens: u64,
    /// Epoch length in seconds.
    pub epoch_length_secs: u64,
    /// Longest a signed request may live, in seconds.
    pub max_request_lifetime_secs: u64,
    /// Whether the RP returns each signature before the request is forwarded.
    pub early_return: bool,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            first_funding_units: 4,
            top_up_units: 2,
            unspent_units: 0,
            price_tokens: 1,
            epoch_length_secs: 3_600,
            max_request_lifetime_secs: 600,
            early_return: false,
        }
    }
}

/// Everything the test asserts on.
#[derive(Debug, Clone)]
pub struct FlowReport {
    /// The opened channel.
    pub channel_id: B256,
    /// Epoch every request in the run was billed to.
    pub epoch: u64,
    /// Units admitted before the epoch ran out.
    pub admitted_before_refusal: u64,
    /// The class the collector refused the over-capacity request with.
    pub refusal_class: String,
    /// Units the refusal proof established, verified against the RP's own key.
    pub proven_units: u64,
    /// Units admitted after the top-up.
    pub admitted_after_top_up: u64,
    /// The collector's counters at the end of the run.
    pub stats: Stats,
    /// On-chain `settledUnits` before the epoch closed.
    pub settled_units: u64,
    /// Per-lane high-water marks on chain, lane-ordered.
    pub lane_high_water: Vec<u64>,
    /// Total funded into the epoch.
    pub funded: U256,
    /// The collector's token balance once the epoch closed.
    pub collector_balance: U256,
    /// The escrow's token balance once the epoch closed.
    pub escrow_balance: U256,
    /// Whether the closing settlement marked the epoch closed.
    pub closed: bool,
}

/// Runs the demo end to end against a fresh anvil instance.
///
/// # Errors
/// Returns an error if any step fails. Anvil and the collector stop when this returns.
#[allow(
    clippy::too_many_lines,
    reason = "a linear scenario script reads better whole"
)]
pub async fn run(cfg: FlowConfig) -> Result<FlowReport> {
    let anvil = Anvil::new().try_spawn()?;
    let rpc = anvil.endpoint_url();
    tracing::info!(endpoint = %rpc, "anvil up");

    let deployer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let funder: PrivateKeySigner = anvil.keys()[1].clone().into();
    let spend_key: PrivateKeySigner = anvil.keys()[2].clone().into();
    let collector_key: PrivateKeySigner = anvil.keys()[3].clone().into();

    let as_deployer = chain::wallet_provider(&rpc, &deployer)?;
    let as_funder = chain::wallet_provider(&rpc, &funder)?;
    let as_collector = chain::wallet_provider(&rpc, &collector_key)?;

    let deployment = chain::deploy_all(&as_deployer, deployer.address()).await?;
    tracing::info!(escrow = %deployment.escrow, token = %deployment.token, "contracts deployed");

    chain::register_rp(
        &as_deployer,
        deployment.rp_registry,
        RP_ID,
        deployer.address(),
        spend_key.address(),
    )
    .await?;

    // ── Open ────────────────────────────────────────────────────────────────
    let price = U256::from(cfg.price_tokens) * U256::from(ONE_TOKEN);
    let now = chain::block_timestamp(&as_deployer).await?;
    let settings = ChannelSettings {
        rpId: RP_ID,
        spendKey: spend_key.address(),
        collector: collector_key.address(),
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
    tracing::info!(channel = %channel_id, epoch, price = %price, "channel opened");

    // ── Fund ────────────────────────────────────────────────────────────────
    let total_units = cfg.first_funding_units + cfg.top_up_units + cfg.unspent_units;
    let budget = U256::from(total_units) * price;
    chain::mint(&as_deployer, deployment.token, funder.address(), budget).await?;
    chain::approve(&as_funder, deployment.token, deployment.escrow, budget).await?;

    let first = U256::from(cfg.first_funding_units) * price;
    chain::fund(&as_funder, deployment.escrow, channel_id, epoch, first).await?;
    tracing::info!(units = cfg.first_funding_units, "epoch funded");

    // ── Services ────────────────────────────────────────────────────────────
    let snapshot = ChainSnapshot::new(
        as_collector.clone(),
        deployment.escrow,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let state = collector::Collector::new(
        as_collector.clone(),
        deployment.escrow,
        deployment.chain_id,
        snapshot,
        settings.clone(),
        LedgerConfig {
            max_request_lifetime: cfg.max_request_lifetime_secs,
            ..LedgerConfig::default()
        },
    );
    let (addr, listener) = collector::bind_ephemeral().await?;
    let server = collector::serve(listener, state.clone());
    let collector_url: reqwest::Url = format!("http://{addr}").parse()?;
    tracing::info!(collector = %collector_url, "collector up");

    let mut rp = rp::RpService::new(
        rp::Transport::demo(collector_url),
        spend_key.clone(),
        escrow_domain,
        settings.clone(),
    );
    rp.early_return = cfg.early_return;

    // ── Spend the funded capacity ───────────────────────────────────────────
    let mut admitted_before_refusal = 0;
    for _ in 0..cfg.first_funding_units {
        match rp.one_request().await? {
            Outcome::Admitted(_) => admitted_before_refusal += 1,
            Outcome::Refused(refused) => {
                server.abort();
                bail!(
                    "funded request refused: {} {}",
                    refused.code,
                    refused.message
                );
            }
        }
    }

    // ── The next request must be refused, with a proof ──────────────────────
    let (refusal_class, proven_units) = match rp.one_request().await? {
        Outcome::Admitted(_) => {
            server.abort();
            bail!("the epoch admitted more units than it was funded for");
        }
        Outcome::Refused(refused) => {
            let proven = rp.verify_refusal(epoch, &refused)?;
            (refused.code, proven)
        }
    };
    tracing::info!(class = %refusal_class, proven_units, "refused at capacity");

    // ── Fund more; capacity rises in the same block ─────────────────────────
    let top_up = U256::from(cfg.top_up_units) * price;
    chain::fund(&as_funder, deployment.escrow, channel_id, epoch, top_up).await?;
    let mut admitted_after_top_up = 0;
    for _ in 0..cfg.top_up_units {
        match rp.one_request().await? {
            Outcome::Admitted(_) => admitted_after_top_up += 1,
            Outcome::Refused(refused) => {
                server.abort();
                bail!(
                    "a request refused after a top-up: {} {}",
                    refused.code,
                    refused.message
                );
            }
        }
    }

    // Capacity bought and never spent. The closing settlement pays it out anyway, which is
    // the design intent rather than a leak.
    if cfg.unspent_units > 0 {
        let unspent = U256::from(cfg.unspent_units) * price;
        chain::fund(&as_funder, deployment.escrow, channel_id, epoch, unspent).await?;
    }

    // ── Settle during the epoch ─────────────────────────────────────────────
    state.sweep().await?;
    let on_chain = chain::epoch_state(&as_collector, deployment.escrow, channel_id, epoch).await?;
    let settled_units = on_chain.settledUnits;
    let mut lane_high_water = Vec::new();
    for lane in 0..u32::try_from(settled_units).unwrap_or(u32::MAX) {
        let mark =
            chain::lane_high_water(&as_collector, deployment.escrow, channel_id, epoch, lane)
                .await?;
        if mark == 0 {
            break;
        }
        lane_high_water.push(mark);
    }

    // ── Close after the epoch ends ──────────────────────────────────────────
    let ends_at = epoch_end(&settings, epoch).ok_or_eyre("epoch end overflowed")?;
    as_deployer.anvil_set_next_block_timestamp(ends_at).await?;
    as_deployer.anvil_mine(Some(1), None).await?;
    let closing = state.sweep().await?;

    let final_state =
        chain::epoch_state(&as_collector, deployment.escrow, channel_id, epoch).await?;
    let report = FlowReport {
        channel_id,
        epoch,
        admitted_before_refusal,
        refusal_class,
        proven_units,
        admitted_after_top_up,
        stats: state.stats().await,
        settled_units,
        lane_high_water,
        funded: final_state.funded,
        collector_balance: chain::balance_of(
            &as_deployer,
            deployment.token,
            collector_key.address(),
        )
        .await?,
        escrow_balance: chain::balance_of(&as_deployer, deployment.token, deployment.escrow)
            .await?,
        closed: final_state.closed && closing.closed == 1,
    };

    // Awaiting the aborted handle guarantees the listener is closed before this returns.
    server.abort();
    let _ = server.await;
    Ok(report)
}
