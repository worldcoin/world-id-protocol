//! End-to-end test of a fixed-rate channel against `WorldIDFeeEscrow` on anvil.
//!
//! Gated behind the `e2e` feature: it needs `forge build` artifacts under `contracts/out/` and
//! `anvil` on PATH. The escrow's own bytecode is read at run time rather than bound at compile
//! time, so a stale artifact fails the test with a clear message instead of the build.

// The lib target enforces `unused_crate_dependencies`; this target links the full dev-dep set
// under both feature states, so the lint only produces noise here.
#![allow(unused_crate_dependencies)]

#[cfg(feature = "e2e")]
mod e2e {
    use alloy::{
        network::EthereumWallet,
        primitives::{B256, Bytes, U256},
        providers::{DynProvider, Provider, ProviderBuilder, ext::AnvilApi as _},
        signers::local::PrivateKeySigner,
        sol,
        sol_types::SolCall as _,
    };
    use alloy_node_bindings::Anvil;
    use eyre::{Context as _, OptionExt as _, Result};
    use rand::Rng as _;
    use world_id_fee_escrow::{
        LaneNonce, NonceReservation, Payment,
        typed_data::{ChannelSettings, domain, epoch_end, epoch_of},
        verify_predecessor, verify_reservation,
    };

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

    /// RP the channel pays for.
    const RP_ID: u64 = 7;
    /// One token per unit.
    const PRICE: u128 = 1_000_000_000_000_000_000;
    /// Seconds in a test epoch.
    const EPOCH_LENGTH: u64 = 3_600;
    /// Units funded into the epoch.
    const UNITS: u64 = 4;

    const fn to_sol_settings(settings: &ChannelSettings) -> IWorldIDFeeEscrow::ChannelSettings {
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

    fn to_sol_auth(payment: &Payment) -> IWorldIDFeeEscrow::PaymentAuthorization {
        IWorldIDFeeEscrow::PaymentAuthorization {
            channelNonce: payment.channel_nonce,
            signature: Bytes::from(payment.signature.as_bytes()),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(
        clippy::too_many_lines,
        reason = "a linear end-to-end script reads better whole"
    )]
    async fn channel_opens_funds_settles_and_closes() -> Result<()> {
        let anvil = Anvil::new().try_spawn().context("anvil must be on PATH")?;
        let rpc = anvil.endpoint_url();
        let chain_id = anvil.chain_id();

        let deployer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let funder: PrivateKeySigner = anvil.keys()[1].clone().into();
        let collector: PrivateKeySigner = anvil.keys()[2].clone().into();
        let spend_key: PrivateKeySigner = anvil.keys()[3].clone().into();

        let provider = |signer: &PrivateKeySigner| -> DynProvider {
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(signer.clone()))
                .connect_http(rpc.clone())
                .erased()
        };
        let as_deployer = provider(&deployer);
        let as_funder = provider(&funder);
        let as_collector = provider(&collector);

        // ── Registry and token ──────────────────────────────────────────────────
        let oprf_registry = MockOprfKeyRegistry::deploy(as_deployer.clone()).await?;
        let token = ERC20Mock::deploy(as_deployer.clone()).await?;
        let rp_registry_impl = RpRegistry::deploy(as_deployer.clone()).await?;
        let rp_registry_proxy = ERC1967Proxy::deploy(
            as_deployer.clone(),
            *rp_registry_impl.address(),
            Bytes::from(
                RpRegistry::initializeCall {
                    feeRecipient: deployer.address(),
                    feeToken: *token.address(),
                    registrationFee: U256::ZERO,
                    oprfKeyRegistry: *oprf_registry.address(),
                }
                .abi_encode(),
            ),
        )
        .await?;
        RpRegistry::new(*rp_registry_proxy.address(), as_deployer.clone())
            .register(
                RP_ID,
                deployer.address(),
                spend_key.address(),
                "rp.example".to_string(),
            )
            .send()
            .await?
            .watch()
            .await?;

        // ── Escrow ──────────────────────────────────────────────────────────────
        // Deployed behind the repository's standard proxy, so the registry arrives through
        // `initialize` rather than a constructor argument.
        let escrow_impl = WorldIDFeeEscrow::deploy(as_deployer.clone()).await?;
        let escrow_addr = *ERC1967Proxy::deploy(
            as_deployer.clone(),
            *escrow_impl.address(),
            Bytes::from(
                WorldIDFeeEscrow::initializeCall {
                    rpRegistry: *rp_registry_proxy.address(),
                }
                .abi_encode(),
            ),
        )
        .await?
        .address();
        let escrow_domain = domain(chain_id, escrow_addr);

        // ── Open ────────────────────────────────────────────────────────────────
        let now = as_deployer
            .get_block(alloy::eips::BlockId::latest())
            .await?
            .ok_or_eyre("no latest block")?
            .header
            .timestamp;
        let settings = ChannelSettings {
            rpId: RP_ID,
            spendKey: spend_key.address(),
            collector: collector.address(),
            token: *token.address(),
            pricePerUnit: U256::from(PRICE),
            epochLength: EPOCH_LENGTH,
            // Epoch 0 starts now, so every request in this test falls in epoch 0.
            epochZero: now,
            salt: B256::from(rand::thread_rng().r#gen::<[u8; 32]>()),
        };
        let sol_settings = to_sol_settings(&settings);

        let escrow_as_funder = WorldIDFeeEscrow::new(escrow_addr, as_funder.clone());
        let channel_id = settings.channel_id(&escrow_domain);
        assert_eq!(
            escrow_as_funder
                .computeChannelId(sol_settings.clone())
                .call()
                .await?,
            channel_id,
            "channel id parity with the contract"
        );

        let opened = escrow_as_funder
            .openChannel(sol_settings.clone())
            .send()
            .await?
            .get_receipt()
            .await?;
        let logged = opened
            .inner
            .logs()
            .iter()
            .find_map(|log| log.log_decode::<WorldIDFeeEscrow::ChannelOpened>().ok())
            .ok_or_eyre("openChannel emitted no ChannelOpened")?;
        assert_eq!(logged.inner.channelId, channel_id);

        // ── Fund one epoch ──────────────────────────────────────────────────────
        let deposit = U256::from(UNITS) * U256::from(PRICE);
        ERC20Mock::new(*token.address(), as_deployer.clone())
            .mint(funder.address(), deposit)
            .send()
            .await?
            .watch()
            .await?;
        ERC20Mock::new(*token.address(), as_funder.clone())
            .approve(escrow_addr, deposit)
            .send()
            .await?
            .watch()
            .await?;

        let epoch = epoch_of(now, &settings).ok_or_eyre("now has no epoch")?;
        escrow_as_funder
            .fund(channel_id, epoch, deposit)
            .send()
            .await?
            .watch()
            .await?;
        let state = escrow_as_funder
            .epochState(channel_id, epoch)
            .call()
            .await?;
        assert_eq!(state.funded, deposit);

        // ── Sign the epoch's units ──────────────────────────────────────────────
        // No collector here: this test is the library against the contract. It plays both
        // sides of the nonce protocol, so a lane's counters walk 1..=UNITS and each signature
        // is checked the way a stateless RP would check the one before it.
        let mut previous: Option<Payment> = None;
        for unit in 1..=UNITS {
            let lane_nonce = LaneNonce::new(0, unit);

            // What a collector would send to hold the lane, and what the RP checks back.
            let reservation = NonceReservation::new(channel_id, epoch, now);
            let signed = reservation.sign(&spend_key, &escrow_domain)?;
            verify_reservation(
                channel_id,
                epoch,
                now,
                &signed,
                spend_key.address(),
                &escrow_domain,
                now,
            )?;
            verify_predecessor(
                previous.as_ref(),
                channel_id,
                epoch,
                lane_nonce,
                spend_key.address(),
                &escrow_domain,
            )?;

            let payment = Payment::sign(channel_id, epoch, lane_nonce, &spend_key, &escrow_domain)?;
            assert_eq!(
                payment.verify(channel_id, epoch, spend_key.address(), &escrow_domain)?,
                lane_nonce,
                "unit {unit}"
            );
            previous = Some(payment);
        }

        // One signature per lane proves the lane's whole usage, so the batch is one entry.
        let batch = vec![previous.clone().ok_or_eyre("no unit was signed")?];

        // ── Settle during the epoch ─────────────────────────────────────────────
        let escrow_as_collector = WorldIDFeeEscrow::new(escrow_addr, as_collector.clone());
        escrow_as_collector
            .settle(
                channel_id,
                epoch,
                batch.iter().map(to_sol_auth).collect::<Vec<_>>(),
            )
            .send()
            .await?
            .watch()
            .await?;

        let state = escrow_as_collector
            .epochState(channel_id, epoch)
            .call()
            .await?;
        assert_eq!(
            state.settledUnits, UNITS,
            "the escrow counts the same units the ledger admitted"
        );
        assert!(!state.closed, "the epoch has not ended yet");

        let lanes: u64 = {
            let mut total = 0;
            for auth in &batch {
                total += escrow_as_collector
                    .laneHighWater(channel_id, epoch, auth.lane_nonce()?.lane)
                    .call()
                    .await?;
            }
            total
        };
        assert_eq!(lanes, UNITS, "settled units are the sum of lane marks");

        // Replaying the same batch pays nothing.
        let before = ERC20Mock::new(*token.address(), as_collector.clone())
            .balanceOf(collector.address())
            .call()
            .await?;
        escrow_as_collector
            .settle(
                channel_id,
                epoch,
                batch.iter().map(to_sol_auth).collect::<Vec<_>>(),
            )
            .send()
            .await?
            .watch()
            .await?;
        assert_eq!(
            ERC20Mock::new(*token.address(), as_collector.clone())
                .balanceOf(collector.address())
                .call()
                .await?,
            before,
            "a stale batch is skipped, not paid twice"
        );

        // ── Close after the epoch ends ──────────────────────────────────────────
        let ends_at = epoch_end(&settings, epoch).ok_or_eyre("epoch end overflowed")?;
        as_deployer.anvil_set_next_block_timestamp(ends_at).await?;
        as_deployer.anvil_mine(Some(1), None).await?;

        let closing = escrow_as_collector
            .settle(channel_id, epoch, Vec::new())
            .send()
            .await?
            .get_receipt()
            .await?;
        let settled = closing
            .inner
            .logs()
            .iter()
            .find_map(|log| log.log_decode::<WorldIDFeeEscrow::EpochSettled>().ok())
            .ok_or_eyre("the closing settle emitted no EpochSettled")?;
        assert!(settled.inner.closed, "an empty batch after the end closes");

        let state = escrow_as_collector
            .epochState(channel_id, epoch)
            .call()
            .await?;
        assert!(state.closed);
        assert_eq!(
            ERC20Mock::new(*token.address(), as_collector.clone())
                .balanceOf(collector.address())
                .call()
                .await?,
            deposit,
            "once closed, paid equals funded: nothing returns to the funder"
        );
        assert_eq!(
            ERC20Mock::new(*token.address(), as_collector.clone())
                .balanceOf(escrow_addr)
                .call()
                .await?,
            U256::ZERO,
            "the escrow keeps nothing"
        );

        Ok(())
    }
}
