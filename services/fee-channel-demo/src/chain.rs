//! Contract bindings, deployment helpers, and the collector's chain snapshot.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use alloy::{
    eips::BlockId,
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall as _,
};
use eyre::{Context as _, OptionExt as _, Result, eyre};
use world_id_fee_escrow::{ChainView, Payment, StaleOrUnavailable, typed_data::ChannelSettings};

sol!(
    #[sol(rpc)]
    ERC1967Proxy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/ERC1967Proxy.sol/ERC1967Proxy.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    RpRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/RpRegistry.sol/RpRegistry.json"
    )
);

sol!(
    #[sol(rpc)]
    MockOprfKeyRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/CredentialSchemaIssuerRegistry.t.sol/MockOprfKeyRegistry.json"
    )
);

sol!(
    #[sol(rpc)]
    ERC20Mock,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/ERC20Mock.sol/ERC20Mock.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc, ignore_unlinked)]
    WorldIDFeeEscrow,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/WorldIDFeeEscrow.sol/WorldIDFeeEscrow.json"
    )
);

/// Addresses of everything the demo deploys.
#[derive(Debug, Clone, Copy)]
pub struct Deployment {
    /// Chain the contracts live on.
    pub chain_id: u64,
    /// `RpRegistry` proxy.
    pub rp_registry: Address,
    /// The ERC-20 the channel is denominated in.
    pub token: Address,
    /// `WorldIDFeeEscrow`, deployed without a proxy.
    pub escrow: Address,
}

/// Builds a provider that signs with `signer`.
///
/// # Errors
/// Returns an error if the endpoint cannot be used.
pub fn wallet_provider(rpc: &reqwest::Url, signer: &PrivateKeySigner) -> Result<DynProvider> {
    Ok(ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer.clone()))
        .connect_http(rpc.clone())
        .erased())
}

/// Deploys the RP registry, the token, and the escrow.
///
/// # Errors
/// Returns an error if any deployment or initialisation call fails.
pub async fn deploy_all(provider: &DynProvider, deployer: Address) -> Result<Deployment> {
    let oprf_registry = MockOprfKeyRegistry::deploy(provider.clone()).await?;
    let token = ERC20Mock::deploy(provider.clone()).await?;
    let rp_registry_impl = RpRegistry::deploy(provider.clone()).await?;
    let rp_registry = ERC1967Proxy::deploy(
        provider.clone(),
        *rp_registry_impl.address(),
        Bytes::from(
            RpRegistry::initializeCall {
                feeRecipient: deployer,
                feeToken: *token.address(),
                registrationFee: U256::ZERO,
                oprfKeyRegistry: *oprf_registry.address(),
            }
            .abi_encode(),
        ),
    )
    .await?;

    // The escrow sits behind the repository's standard proxy, so the registry arrives through
    // `initialize` rather than a constructor argument.
    let escrow_impl = WorldIDFeeEscrow::deploy(provider.clone()).await?;
    let escrow = *ERC1967Proxy::deploy(
        provider.clone(),
        *escrow_impl.address(),
        Bytes::from(
            WorldIDFeeEscrow::initializeCall {
                rpRegistry: *rp_registry.address(),
            }
            .abi_encode(),
        ),
    )
    .await?
    .address();

    Ok(Deployment {
        chain_id: provider.get_chain_id().await?,
        rp_registry: *rp_registry.address(),
        token: *token.address(),
        escrow,
    })
}

/// Registers `rp_id` with the given manager and request-signing key.
///
/// # Errors
/// Returns an error if the registration transaction reverts.
pub async fn register_rp(
    provider: &DynProvider,
    rp_registry: Address,
    rp_id: u64,
    manager: Address,
    signer: Address,
) -> Result<()> {
    RpRegistry::new(rp_registry, provider.clone())
        .register(rp_id, manager, signer, "rp.example".to_string())
        .send()
        .await?
        .watch()
        .await?;
    Ok(())
}

/// Mints `amount` of the demo token to `to`.
///
/// # Errors
/// Returns an error if the mint transaction reverts.
pub async fn mint(provider: &DynProvider, token: Address, to: Address, amount: U256) -> Result<()> {
    ERC20Mock::new(token, provider.clone())
        .mint(to, amount)
        .send()
        .await?
        .watch()
        .await?;
    Ok(())
}

/// Approves `spender` to move `amount` of the caller's tokens.
///
/// # Errors
/// Returns an error if the approval transaction reverts.
pub async fn approve(
    provider: &DynProvider,
    token: Address,
    spender: Address,
    amount: U256,
) -> Result<()> {
    ERC20Mock::new(token, provider.clone())
        .approve(spender, amount)
        .send()
        .await?
        .watch()
        .await?;
    Ok(())
}

/// Reads a token balance.
///
/// # Errors
/// Returns an error if the call fails.
pub async fn balance_of(provider: &DynProvider, token: Address, of: Address) -> Result<U256> {
    Ok(ERC20Mock::new(token, provider.clone())
        .balanceOf(of)
        .call()
        .await?)
}

/// The latest block's timestamp, the clock the escrow's epochs are measured against.
///
/// # Errors
/// Returns an error if the block cannot be read.
pub async fn block_timestamp(provider: &DynProvider) -> Result<u64> {
    Ok(provider
        .get_block(BlockId::latest())
        .await?
        .ok_or_eyre("no latest block")?
        .header
        .timestamp)
}

/// Registers a channel and returns its id, checking the contract agrees with the Rust digest.
///
/// # Errors
/// Returns an error if the transaction reverts or the ids disagree.
pub async fn open_channel(
    provider: &DynProvider,
    escrow: Address,
    settings: &ChannelSettings,
    expected: B256,
) -> Result<B256> {
    let receipt = WorldIDFeeEscrow::new(escrow, provider.clone())
        .openChannel(to_sol_settings(settings))
        .send()
        .await?
        .get_receipt()
        .await?;
    let opened = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| log.log_decode::<WorldIDFeeEscrow::ChannelOpened>().ok())
        .ok_or_eyre("openChannel emitted no ChannelOpened")?;
    if opened.inner.channelId != expected {
        return Err(eyre!(
            "channel id mismatch: contract {} vs computed {expected}",
            opened.inner.channelId
        ));
    }
    Ok(opened.inner.channelId)
}

/// Buys capacity for one epoch.
///
/// # Errors
/// Returns an error if the transaction reverts.
pub async fn fund(
    provider: &DynProvider,
    escrow: Address,
    channel_id: B256,
    epoch: u64,
    amount: U256,
) -> Result<()> {
    WorldIDFeeEscrow::new(escrow, provider.clone())
        .fund(channel_id, epoch, amount)
        .send()
        .await?
        .watch()
        .await?;
    Ok(())
}

/// What one `settle` call did.
#[derive(Debug, Clone, Copy)]
pub struct Settlement {
    /// Sum of lane high-water marks after the call.
    pub settled_units: u64,
    /// Tokens this call moved to the collector.
    pub paid: U256,
    /// Whether the call also closed the epoch.
    pub closed: bool,
}

/// Raises lane marks and pays the collector; an empty batch after the epoch ends closes it.
///
/// # Errors
/// Returns an error if the transaction reverts or emits no `EpochSettled`.
pub async fn settle(
    provider: &DynProvider,
    escrow: Address,
    channel_id: B256,
    epoch: u64,
    auths: &[Payment],
) -> Result<Settlement> {
    let receipt = WorldIDFeeEscrow::new(escrow, provider.clone())
        .settle(
            channel_id,
            epoch,
            auths.iter().map(to_sol_auth).collect::<Vec<_>>(),
        )
        .send()
        .await
        .with_context(|| {
            format!(
                "settle reverted for channel {channel_id} epoch {epoch} with {} authorisation(s)",
                auths.len()
            )
        })?
        .get_receipt()
        .await?;
    let settled = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| log.log_decode::<WorldIDFeeEscrow::EpochSettled>().ok())
        .ok_or_eyre("settle emitted no EpochSettled")?;
    Ok(Settlement {
        settled_units: settled.inner.settledUnits,
        paid: settled.inner.paid,
        closed: settled.inner.closed,
    })
}

/// Reads `epochState`.
///
/// # Errors
/// Returns an error if the call fails.
pub async fn epoch_state(
    provider: &DynProvider,
    escrow: Address,
    channel_id: B256,
    epoch: u64,
) -> Result<IWorldIDFeeEscrow::EpochState> {
    Ok(WorldIDFeeEscrow::new(escrow, provider.clone())
        .epochState(channel_id, epoch)
        .call()
        .await?)
}

/// Reads a lane's settled high-water mark.
///
/// # Errors
/// Returns an error if the call fails.
pub async fn lane_high_water(
    provider: &DynProvider,
    escrow: Address,
    channel_id: B256,
    epoch: u64,
    lane: u32,
) -> Result<u64> {
    Ok(WorldIDFeeEscrow::new(escrow, provider.clone())
        .laneHighWater(channel_id, epoch, lane)
        .call()
        .await?)
}

/// Converts the signing crate's settings into the contract binding's equivalent.
#[must_use]
pub const fn to_sol_settings(settings: &ChannelSettings) -> IWorldIDFeeEscrow::ChannelSettings {
    IWorldIDFeeEscrow::ChannelSettings {
        rpId: settings.rpId,
        spendKey: settings.spendKey,
        collector: settings.collector,
        token: settings.token,
        pricePerUnit: settings.pricePerUnit,
        epochLength: settings.epochLength,
        epochZero: settings.epochZero,
        salt: settings.salt,
    }
}

/// Converts a payment into the struct `settle` takes. The epoch is the call's argument.
#[must_use]
pub fn to_sol_auth(payment: &Payment) -> IWorldIDFeeEscrow::PaymentAuthorization {
    IWorldIDFeeEscrow::PaymentAuthorization {
        channelNonce: payment.channel_nonce,
        signature: Bytes::from(payment.signature.as_bytes()),
    }
}

/// One cached capacity reading.
#[derive(Debug, Clone, Copy)]
struct Reading {
    capacity: u64,
    at: Instant,
}

/// The collector's view of funded capacity, refreshed from the escrow and bounded by age.
///
/// [`ChainView::capacity`] is synchronous because the ledger is, so the async refresh runs
/// separately and this only ever reads the cache. A reading older than `max_staleness`, or a
/// channel never read at all, refuses rather than guesses.
#[derive(Debug, Clone)]
pub struct ChainSnapshot {
    provider: DynProvider,
    escrow: Address,
    max_staleness: Duration,
    read_timeout: Duration,
    prices: Arc<RwLock<HashMap<B256, U256>>>,
    readings: Arc<RwLock<HashMap<(B256, u64), Reading>>>,
}

impl ChainSnapshot {
    /// Creates an empty snapshot reading from the escrow at `escrow`.
    #[must_use]
    pub fn new(
        provider: DynProvider,
        escrow: Address,
        max_staleness: Duration,
        read_timeout: Duration,
    ) -> Self {
        Self {
            provider,
            escrow,
            max_staleness,
            read_timeout,
            prices: Arc::new(RwLock::new(HashMap::new())),
            readings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Records the price a channel's capacity is derived from.
    pub fn track(&self, channel_id: B256, price_per_unit: U256) {
        if let Ok(mut prices) = self.prices.write() {
            prices.insert(channel_id, price_per_unit);
        }
    }

    /// Reads `epochState` and caches `funded / pricePerUnit`.
    ///
    /// Bounded by `read_timeout`. A failure leaves the previous reading in place to age out,
    /// so a brief RPC blip does not immediately refuse traffic but a sustained one does.
    ///
    /// # Errors
    /// Returns an error if the channel is untracked, the read times out, or the call fails.
    pub async fn refresh(&self, channel_id: B256, epoch: u64) -> Result<u64> {
        let price = self
            .prices
            .read()
            .ok()
            .and_then(|prices| prices.get(&channel_id).copied())
            .ok_or_else(|| eyre!("channel {channel_id} is not tracked"))?;
        if price.is_zero() {
            return Err(eyre!("channel {channel_id} has a zero price"));
        }

        let state = tokio::time::timeout(
            self.read_timeout,
            epoch_state(&self.provider, self.escrow, channel_id, epoch),
        )
        .await
        .map_err(|_| eyre!("epochState timed out after {:?}", self.read_timeout))??;

        let capacity = u64::try_from(state.funded / price).unwrap_or(u64::MAX);
        if let Ok(mut readings) = self.readings.write() {
            readings.insert(
                (channel_id, epoch),
                Reading {
                    capacity,
                    at: Instant::now(),
                },
            );
        }
        Ok(capacity)
    }
}

impl ChainView for ChainSnapshot {
    fn capacity(&self, channel_id: B256, epoch: u64) -> Result<u64, StaleOrUnavailable> {
        let stale = |reason: &str| StaleOrUnavailable {
            channel_id,
            epoch,
            reason: reason.to_string(),
        };
        let reading = {
            let readings = self.readings.read().map_err(|_| stale("cache poisoned"))?;
            readings
                .get(&(channel_id, epoch))
                .copied()
                .ok_or_else(|| stale("never read"))?
        };
        let age = reading.at.elapsed();
        if age > self.max_staleness {
            return Err(stale(&format!(
                "reading is {age:?} old, bound is {:?}",
                self.max_staleness
            )));
        }
        Ok(reading.capacity)
    }
}
