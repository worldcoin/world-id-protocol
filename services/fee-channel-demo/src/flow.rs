//! The whole scenario, shared by the demo binary and the integration test.

use alloy::{
    primitives::{B256, U256},
    providers::ext::AnvilApi as _,
    signers::local::PrivateKeySigner,
};
use alloy_node_bindings::Anvil;
use eyre::{Result, eyre};
use rand::Rng as _;
use world_id_fee_escrow::typed_data::{self, ChannelSettings};
use world_id_primitives::{OprfKeyId, rp::RpId};

use crate::{
    chain::{self, ERC20Mock, WorldIDFeeEscrow},
    collector, nonce_manager, rp,
};

/// The RP this demo registers and pays for.
const RP_ID: u64 = 7;
/// One WLD, in wei.
const ONE_WLD: u128 = 1_000_000_000_000_000_000;

/// Knobs for one run of the demo.
#[derive(Debug, Clone, Copy)]
pub struct FlowConfig {
    /// Independent nonce lanes on the channel.
    pub lane_count: u32,
    /// Concurrent RP workers.
    pub workers: usize,
    /// Requests each worker issues.
    pub requests_per_worker: usize,
    /// WLD the payer escrows.
    pub deposit_wld: u64,
    /// WLD charged per verification before the decay begins.
    pub price_wld: u64,
    /// Verifications priced at the flat marginal rate; past this the fee decays.
    pub threshold: u64,
    /// Admissions between automatic settlements.
    pub settle_every: usize,
    /// Seconds the collector has to settle.
    pub collection_window_secs: u64,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            lane_count: 3,
            workers: 3,
            requests_per_worker: 10,
            deposit_wld: 8,
            price_wld: 1,
            threshold: 4,
            settle_every: 5,
            collection_window_secs: 600,
        }
    }
}

/// Everything the test asserts on.
#[derive(Debug, Clone)]
pub struct FlowReport {
    /// The opened channel.
    pub channel_id: B256,
    /// Requests the collector admitted.
    pub admitted: usize,
    /// Requests refused for want of funds.
    pub rejected_insolvent: usize,
    /// Requests refused for any other reason.
    pub rejected_other: usize,
    /// Reasons the RP saw, in completion order.
    pub rejection_reasons: Vec<String>,
    /// `settle` transactions sent.
    pub settlements: usize,
    /// The collector's WLD balance after the run.
    pub collector_wld: U256,
    /// The payer's WLD balance after the channel closed.
    pub payer_wld_after_close: U256,
    /// The escrow's WLD balance after the channel closed.
    pub escrow_wld_after_close: U256,
    /// On-chain Σ lane high-water marks.
    pub settled_count: U256,
    /// On-chain high-water mark per lane.
    pub lane_high_water: Vec<u64>,
    /// The nonce manager's counter per lane.
    pub manager_lane_counters: Vec<u64>,
    /// Lanes whose latest recorded request verifies against the RP's spend key.
    pub manager_latest_verified: usize,
    /// WLD returned to the payer on close.
    pub refund: U256,
    /// The schedule's ceiling, `2 * price * threshold`.
    pub max_fee: U256,
    /// `cumulativeFee(settled_count)` read from the deployed schedule.
    pub cumulative_fee_at_end: U256,
    /// `cumulativeFee(k)` for `k` in `0..=settled_count`, read from the deployed schedule.
    pub cumulative_fee_curve: Vec<U256>,
}

/// Runs the demo end to end against a fresh anvil instance.
///
/// # Errors
/// Returns an error if any step fails. Anvil and both services stop when this returns.
#[allow(
    clippy::too_many_lines,
    reason = "a linear scenario script reads better whole"
)]
pub async fn run(cfg: FlowConfig) -> Result<FlowReport> {
    let anvil = Anvil::new().try_spawn()?;
    let rpc = anvil.endpoint_url();
    tracing::info!(endpoint = %rpc, "anvil up");

    let deployer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let payer: PrivateKeySigner = anvil.keys()[1].clone().into();
    let spend_key: PrivateKeySigner = anvil.keys()[2].clone().into();
    let collector_key: PrivateKeySigner = anvil.keys()[3].clone().into();

    let as_deployer = chain::wallet_provider(&rpc, &deployer)?;
    let as_payer = chain::wallet_provider(&rpc, &payer)?;
    let as_collector = chain::wallet_provider(&rpc, &collector_key)?;

    let price = U256::from(cfg.price_wld) * U256::from(ONE_WLD);
    let deployment = chain::deploy_all(
        &as_deployer,
        deployer.address(),
        price,
        U256::from(cfg.threshold),
    )
    .await?;
    tracing::info!(
        escrow = %deployment.escrow,
        wld = %deployment.wld,
        fee_schedule = %deployment.fee_schedule,
        "contracts deployed"
    );

    chain::register_rp(
        &as_deployer,
        deployment.rp_registry,
        RP_ID,
        payer.address(),
        spend_key.address(),
    )
    .await?;
    tracing::info!(rp_id = RP_ID, spend_key = %spend_key.address(), "rp registered");

    let deposit = U256::from(cfg.deposit_wld) * U256::from(ONE_WLD);
    chain::mint_wld(&as_deployer, deployment.wld, payer.address(), deposit).await?;
    ERC20Mock::new(deployment.wld, as_payer.clone())
        .approve(deployment.escrow, deposit)
        .send()
        .await?
        .watch()
        .await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let settings = ChannelSettings {
        rpId: RP_ID,
        payer: payer.address(),
        spendKey: spend_key.address(),
        collector: collector_key.address(),
        token: deployment.wld,
        feeSchedule: deployment.fee_schedule,
        laneCount: cfg.lane_count,
        collectionDeadline: now + cfg.collection_window_secs,
        salt: B256::from(rand::thread_rng().r#gen::<[u8; 32]>()),
    };
    let domain = typed_data::domain(deployment.chain_id, deployment.escrow);
    let channel_id = typed_data::channel_id(deployment.chain_id, deployment.escrow, &settings);
    let rp_signature = typed_data::sign_open_channel(&spend_key, &settings, &domain)?;

    let escrow_as_payer = WorldIDFeeEscrow::new(deployment.escrow, as_payer.clone());
    let open_receipt = escrow_as_payer
        .openChannel(
            chain::to_sol_settings(&settings),
            deposit,
            alloy::primitives::Bytes::from(rp_signature.as_bytes()),
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    let opened = open_receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| log.log_decode::<WorldIDFeeEscrow::ChannelOpened>().ok())
        .ok_or_else(|| eyre!("openChannel emitted no ChannelOpened log"))?;
    if opened.inner.channelId != channel_id {
        return Err(eyre!(
            "channel id mismatch: log {} vs computed {channel_id}",
            opened.inner.channelId
        ));
    }
    tracing::info!(channel = %channel_id, deposit = %deposit, lanes = cfg.lane_count, "channel opened");

    // ── Services ────────────────────────────────────────────────────────────
    let manager_state = nonce_manager::state();
    let (manager_addr, manager_listener) = nonce_manager::bind_ephemeral().await?;
    let manager_task = nonce_manager::serve(manager_listener, manager_state.clone());

    let collector_state = collector::Collector::new(
        as_collector.clone(),
        deployment.escrow,
        deployment.fee_schedule,
        domain.clone(),
        cfg.settle_every,
    );
    let (collector_addr, collector_listener) = nonce_manager::bind_ephemeral().await?;
    let collector_task = collector::serve(collector_listener, collector_state.clone());

    let manager_url: reqwest::Url = format!("http://{manager_addr}").parse()?;
    let collector_url: reqwest::Url = format!("http://{collector_addr}").parse()?;
    tracing::info!(nonce_manager = %manager_url, collector = %collector_url, "services up");

    let http = reqwest::Client::new();
    http.post(manager_url.join("/channels")?)
        .json(&nonce_manager::RegisterChannel {
            channel_id,
            lane_count: cfg.lane_count,
        })
        .send()
        .await?
        .error_for_status()?;

    // ── The RP does its work ────────────────────────────────────────────────
    let rp = rp::RpService::new(
        manager_url.clone(),
        collector_url.clone(),
        spend_key.clone(),
        domain.clone(),
        channel_id,
        RpId::new(RP_ID),
        OprfKeyId::new(alloy::primitives::Uint::<160, 3>::from(1u64)),
    );
    let rp_report = rp.run(cfg.workers, cfg.requests_per_worker).await?;
    tracing::info!(
        admitted = rp_report.admitted,
        rejected = rp_report.rejected.len(),
        "rp finished"
    );

    http.post(collector_url.join("/settle")?)
        .send()
        .await?
        .error_for_status()?;
    let stats = collector_state.stats().await;

    // ── Read everything back ────────────────────────────────────────────────
    let manager_status: nonce_manager::ChannelStatus = http
        .get(manager_url.join(&format!("/channels/{channel_id}"))?)
        .send()
        .await?
        .json()
        .await?;
    let manager_lane_counters = manager_status.lanes.iter().map(|l| l.counter).collect();

    // Every request the manager kept must still verify under the RP's own key. This is the
    // same check the RP runs on `previous` before trusting a lease.
    let manager_latest_verified =
        manager_state
            .lock()
            .await
            .get(&channel_id)
            .map_or(0, |channel| {
                channel
                    .lanes
                    .iter()
                    .filter(|lane| {
                        lane.latest
                            .as_ref()
                            .is_some_and(|req| req.verify(&domain, spend_key.address()).is_ok())
                    })
                    .count()
            });

    let channel = escrow_as_payer.getChannel(channel_id).call().await?;
    let mut lane_high_water = Vec::with_capacity(cfg.lane_count as usize);
    for lane in 0..cfg.lane_count {
        lane_high_water.push(
            escrow_as_payer
                .laneHighWater(channel_id, lane)
                .call()
                .await?,
        );
    }
    let collector_wld =
        chain::wld_balance(&as_deployer, deployment.wld, collector_key.address()).await?;
    let max_fee = chain::max_fee(&as_deployer, deployment.fee_schedule).await?;
    let cumulative_fee_at_end =
        chain::cumulative_fee(&as_deployer, deployment.fee_schedule, channel.settledCount).await?;

    // The whole curve up to the settled count, so callers can inspect the marginal price
    // without needing the chain to still be running.
    let mut cumulative_fee_curve = Vec::new();
    for k in 0..=u64::try_from(channel.settledCount).unwrap_or(0) {
        cumulative_fee_curve.push(
            chain::cumulative_fee(&as_deployer, deployment.fee_schedule, U256::from(k)).await?,
        );
    }

    // ── Close after the collection window ───────────────────────────────────
    as_deployer
        .anvil_increase_time(cfg.collection_window_secs + 1)
        .await?;
    as_deployer.anvil_mine(Some(1), None).await?;

    let close_receipt = escrow_as_payer
        .closeChannel(channel_id)
        .send()
        .await?
        .get_receipt()
        .await?;
    let closed = close_receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| log.log_decode::<WorldIDFeeEscrow::ChannelClosed>().ok())
        .ok_or_else(|| eyre!("closeChannel emitted no ChannelClosed log"))?;
    let refund = closed.inner.refundedToPayer;
    tracing::info!(refund = %refund, "channel closed");

    // Awaiting the aborted handles guarantees both listeners are closed before this returns,
    // rather than at some later point in the runtime's shutdown.
    manager_task.abort();
    collector_task.abort();
    let _ = manager_task.await;
    let _ = collector_task.await;

    Ok(FlowReport {
        channel_id,
        admitted: stats.admitted,
        rejected_insolvent: stats.rejected_insolvent,
        rejected_other: stats.rejected_other,
        rejection_reasons: rp_report.rejected,
        settlements: stats.settlements,
        collector_wld,
        payer_wld_after_close: chain::wld_balance(&as_deployer, deployment.wld, payer.address())
            .await?,
        escrow_wld_after_close: chain::wld_balance(&as_deployer, deployment.wld, deployment.escrow)
            .await?,
        settled_count: channel.settledCount,
        lane_high_water,
        manager_lane_counters,
        manager_latest_verified,
        refund,
        max_fee,
        cumulative_fee_at_end,
        cumulative_fee_curve,
    })
}
