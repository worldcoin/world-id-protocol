//! Contract bindings and the on-chain reads the demo services need.

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall as _,
};
use eyre::{Result, eyre};
use world_id_fee_escrow::{collector::ChannelView, typed_data};

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
    #[sol(rpc)]
    FixedFeeSchedule,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/FixedFeeSchedule.sol/FixedFeeSchedule.json"
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
    /// The ERC-20 standing in for WLD.
    pub wld: Address,
    /// `FixedFeeSchedule` pricing the channel.
    pub fee_schedule: Address,
    /// `WorldIDFeeEscrow` proxy.
    pub escrow: Address,
}

/// Builds a provider that signs with `signer`.
///
/// # Errors
/// Returns an error if the endpoint cannot be parsed.
pub fn wallet_provider(rpc: &reqwest::Url, signer: &PrivateKeySigner) -> Result<DynProvider> {
    Ok(ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer.clone()))
        .connect_http(rpc.clone())
        .erased())
}

/// Deploys the registry, the WLD mock, the fee schedule, and the escrow.
///
/// # Errors
/// Returns an error if any deployment or initialisation call fails.
pub async fn deploy_all(
    provider: &DynProvider,
    deployer: Address,
    price: U256,
) -> Result<Deployment> {
    let oprf_registry = MockOprfKeyRegistry::deploy(provider.clone()).await?;
    let wld = ERC20Mock::deploy(provider.clone()).await?;
    let rp_registry_impl = RpRegistry::deploy(provider.clone()).await?;
    let rp_registry = ERC1967Proxy::deploy(
        provider.clone(),
        *rp_registry_impl.address(),
        Bytes::from(
            RpRegistry::initializeCall {
                feeRecipient: deployer,
                feeToken: *wld.address(),
                registrationFee: U256::ZERO,
                oprfKeyRegistry: *oprf_registry.address(),
            }
            .abi_encode(),
        ),
    )
    .await?;

    let fee_schedule = FixedFeeSchedule::deploy(provider.clone(), price).await?;
    let escrow_impl = WorldIDFeeEscrow::deploy(provider.clone()).await?;
    let escrow = ERC1967Proxy::deploy(
        provider.clone(),
        *escrow_impl.address(),
        Bytes::from(
            WorldIDFeeEscrow::initializeCall {
                rpRegistry: *rp_registry.address(),
            }
            .abi_encode(),
        ),
    )
    .await?;

    Ok(Deployment {
        chain_id: provider.get_chain_id().await?,
        rp_registry: *rp_registry.address(),
        wld: *wld.address(),
        fee_schedule: *fee_schedule.address(),
        escrow: *escrow.address(),
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

/// Mints `amount` WLD to `to`.
///
/// # Errors
/// Returns an error if the mint transaction reverts.
pub async fn mint_wld(
    provider: &DynProvider,
    wld: Address,
    to: Address,
    amount: U256,
) -> Result<()> {
    ERC20Mock::new(wld, provider.clone())
        .mint(to, amount)
        .send()
        .await?
        .watch()
        .await?;
    Ok(())
}

/// Reads a WLD balance.
///
/// # Errors
/// Returns an error if the call fails.
pub async fn wld_balance(provider: &DynProvider, wld: Address, of: Address) -> Result<U256> {
    Ok(ERC20Mock::new(wld, provider.clone())
        .balanceOf(of)
        .call()
        .await?)
}

/// Snapshots on-chain channel state for the collector's ledger.
///
/// # Errors
/// Returns an error if `getChannel` fails or the channel does not exist.
pub async fn read_channel_view(
    provider: &DynProvider,
    escrow: Address,
    channel_id: B256,
) -> Result<ChannelView> {
    let channel = WorldIDFeeEscrow::new(escrow, provider.clone())
        .getChannel(channel_id)
        .call()
        .await?;
    if channel.openedAt == 0 {
        return Err(eyre!("channel {channel_id} does not exist"));
    }
    Ok(ChannelView {
        channel_id,
        settings: to_escrow_settings(&channel.settings),
        balance: channel.balance,
        paid: channel.paid,
        settled_count: channel.settledCount,
    })
}

/// Reads the schedule's cumulative fee for `count` units of work.
///
/// # Errors
/// Returns an error if the call fails.
pub async fn cumulative_fee(
    provider: &DynProvider,
    fee_schedule: Address,
    count: U256,
) -> Result<U256> {
    Ok(FixedFeeSchedule::new(fee_schedule, provider.clone())
        .cumulativeFee(count)
        .call()
        .await?)
}

/// Converts the contract binding's settings into the signing crate's equivalent.
#[must_use]
pub const fn to_escrow_settings(
    settings: &IWorldIDFeeEscrow::ChannelSettings,
) -> typed_data::ChannelSettings {
    typed_data::ChannelSettings {
        rpId: settings.rpId,
        payer: settings.payer,
        spendKey: settings.spendKey,
        collector: settings.collector,
        token: settings.token,
        feeSchedule: settings.feeSchedule,
        laneCount: settings.laneCount,
        collectionDeadline: settings.collectionDeadline,
        salt: settings.salt,
    }
}

/// Converts the signing crate's settings into the contract binding's equivalent.
#[must_use]
pub const fn to_sol_settings(
    settings: &typed_data::ChannelSettings,
) -> IWorldIDFeeEscrow::ChannelSettings {
    IWorldIDFeeEscrow::ChannelSettings {
        rpId: settings.rpId,
        payer: settings.payer,
        spendKey: settings.spendKey,
        collector: settings.collector,
        token: settings.token,
        feeSchedule: settings.feeSchedule,
        laneCount: settings.laneCount,
        collectionDeadline: settings.collectionDeadline,
        salt: settings.salt,
    }
}

/// Converts a ledger authorisation into the struct `settle` takes.
#[must_use]
pub fn to_sol_auth(
    auth: &world_id_fee_escrow::OnchainPaymentAuthorization,
) -> IWorldIDFeeEscrow::PaymentAuthorization {
    IWorldIDFeeEscrow::PaymentAuthorization {
        channelNonce: alloy::primitives::Uint::<96, 2>::from(auth.channel_nonce),
        rpRequestDigest: auth.rp_request_digest,
        signature: auth.signature.clone(),
    }
}
