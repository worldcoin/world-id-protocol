//! End-to-end test of a YABS channel against `WorldIDFeeEscrow` on anvil.
//!
//! Gated behind the `e2e` feature because the `sol!` bindings need `forge build` artifacts
//! under `contracts/out/` at compile time, and `anvil` on PATH at run time.

// The lib target enforces `unused_crate_dependencies`; this target links the full dev-dep set
// under both feature states, so the lint only produces noise here.
#![allow(unused_crate_dependencies)]

#[cfg(feature = "e2e")]
mod e2e {

    use self::IWorldIDFeeEscrow::{
        ChannelSettings as SolChannelSettings, PaymentAuthorization as SolPaymentAuthorization,
    };
    use alloy::{
        network::EthereumWallet,
        primitives::{B256, Bytes, U256},
        providers::{Provider, ProviderBuilder, ext::AnvilApi as _},
        signers::local::PrivateKeySigner,
        sol,
        sol_types::SolCall as _,
    };
    use alloy_node_bindings::Anvil;
    use eyre::{Context as _, Result};
    use rand::Rng as _;
    use world_id_fee_escrow::{
        collector::{AdmitError, ChannelView, Ledger},
        nonce::NonceAllocator,
        request::ProofRequestV2,
        typed_data::{ChannelSettings, channel_id, domain, sign_open_channel},
    };
    use world_id_primitives::{
        FieldElement, OprfKeyId, SessionRef,
        request::{ProofRequest, ProofType, RequestItem, RequestVersion},
        rp::RpId,
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

    /// RP the channel pays for.
    const RP_ID: u64 = 7;
    /// Lanes on the test channel.
    const LANE_COUNT: u32 = 2;
    /// One token per verification, matching the deployed `FixedFeeSchedule`.
    const PRICE: u128 = 1_000_000_000_000_000_000;

    fn price() -> U256 {
        U256::from(PRICE)
    }

    /// Cumulative fee of the deployed `FixedFeeSchedule(1e18)`.
    fn fee(count: U256) -> U256 {
        count * price()
    }

    /// A minimal uniqueness request; only the digest-covered fields matter here.
    fn base_request(nonce: u64) -> ProofRequest {
        ProofRequest {
            id: format!("req_{nonce}"),
            version: RequestVersion::V2,
            proof_type: ProofType::Uniqueness,
            created_at: 1_700_000_000,
            expires_at: 1_700_100_000,
            rp_id: RpId::new(RP_ID),
            oprf_key_id: OprfKeyId::new(alloy::primitives::Uint::<160, 3>::from(1u64)),
            session_id: SessionRef::None,
            action: Some(FieldElement::from(42u64)),
            signature: alloy::signers::Signature::new(U256::ONE, U256::ONE, false),
            nonce: FieldElement::from(nonce),
            requests: vec![RequestItem::new("orb".to_string(), 1, None, None, None)],
            constraints: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(
        clippy::too_many_lines,
        reason = "a linear end-to-end script reads better whole"
    )]
    async fn channel_opens_settles_and_closes() -> Result<()> {
        let anvil = Anvil::new().try_spawn().context("anvil must be on PATH")?;
        let rpc = anvil.endpoint_url();
        let chain_id = anvil.chain_id();

        let deployer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let payer: PrivateKeySigner = anvil.keys()[1].clone().into();
        let collector: PrivateKeySigner = anvil.keys()[2].clone().into();
        let spend_key: PrivateKeySigner = anvil.keys()[3].clone().into();

        let as_deployer = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.clone()))
            .connect_http(rpc.clone());
        let as_payer = ProviderBuilder::new()
            .wallet(EthereumWallet::from(payer.clone()))
            .connect_http(rpc.clone());
        let as_collector = ProviderBuilder::new()
            .wallet(EthereumWallet::from(collector.clone()))
            .connect_http(rpc.clone());

        // ── Registry ────────────────────────────────────────────────────────────
        let oprf_registry = MockOprfKeyRegistry::deploy(as_deployer.clone()).await?;
        let rp_registry_impl = RpRegistry::deploy(as_deployer.clone()).await?;
        let token = ERC20Mock::deploy(as_deployer.clone()).await?;
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
        let rp_registry = RpRegistry::new(*rp_registry_proxy.address(), as_deployer.clone());
        rp_registry
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
        let schedule = FixedFeeSchedule::deploy(as_deployer.clone(), price()).await?;
        let escrow_impl = WorldIDFeeEscrow::deploy(as_deployer.clone()).await?;
        let escrow_proxy = ERC1967Proxy::deploy(
            as_deployer.clone(),
            *escrow_impl.address(),
            Bytes::from(
                WorldIDFeeEscrow::initializeCall {
                    rpRegistry: *rp_registry_proxy.address(),
                }
                .abi_encode(),
            ),
        )
        .await?;
        let escrow_addr = *escrow_proxy.address();

        // ── Open the channel ────────────────────────────────────────────────────
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let settings = ChannelSettings {
            rpId: RP_ID,
            payer: payer.address(),
            spendKey: spend_key.address(),
            collector: collector.address(),
            token: *token.address(),
            feeSchedule: *schedule.address(),
            laneCount: LANE_COUNT,
            collectionDeadline: now + 3600,
            salt: B256::from(rand::thread_rng().r#gen::<[u8; 32]>()),
        };

        let escrow_as_payer = WorldIDFeeEscrow::new(escrow_addr, as_payer.clone());
        let onchain_cid = escrow_as_payer
            .computeChannelId(to_sol_settings(&settings))
            .call()
            .await?;
        let cid = channel_id(chain_id, escrow_addr, &settings);
        assert_eq!(onchain_cid, cid, "channel id parity with computeChannelId");

        let escrow_domain = domain(chain_id, escrow_addr);
        let onchain_open_hash = escrow_as_payer
            .openChannelHash(to_sol_settings(&settings))
            .call()
            .await?;
        let rp_signature = sign_open_channel(&spend_key, &settings, &escrow_domain)?;
        assert_eq!(
            rp_signature.recover_address_from_prehash(&onchain_open_hash)?,
            spend_key.address(),
            "OpenChannel typed data parity"
        );

        let deposit = U256::from(12u64) * price();
        let token_as_deployer = ERC20Mock::new(*token.address(), as_deployer.clone());
        token_as_deployer
            .mint(payer.address(), U256::from(100u64) * price())
            .send()
            .await?
            .watch()
            .await?;
        ERC20Mock::new(*token.address(), as_payer.clone())
            .approve(escrow_addr, deposit)
            .send()
            .await?
            .watch()
            .await?;
        escrow_as_payer
            .openChannel(
                to_sol_settings(&settings),
                deposit,
                Bytes::from(rp_signature.as_bytes()),
            )
            .send()
            .await?
            .watch()
            .await?;

        // ── Admit ten requests, refuse the eleventh ─────────────────────────────
        let mut allocator = NonceAllocator::new(LANE_COUNT)?;
        let mut ledger = Ledger::new();
        let view = read_view(&escrow_as_payer, cid, &settings).await?;
        assert_eq!(view.balance, deposit);

        for i in 1..=10u64 {
            let request = ProofRequestV2::sign(
                base_request(i),
                cid,
                allocator.next_round_robin()?,
                &spend_key,
                &escrow_domain,
            )?;
            ledger
                .admit(&request, &view, &fee, &escrow_domain)
                .with_context(|| format!("admission {i} must pass"))?;
        }

        // The deposit covers 12 units. A scratch ledger pins that boundary exactly: units 11 and
        // 12 are affordable, unit 13 is not.
        let mut scratch = ledger.clone();
        for i in 11..=12u64 {
            let request = ProofRequestV2::sign(
                base_request(i),
                cid,
                allocator.next_round_robin()?,
                &spend_key,
                &escrow_domain,
            )?;
            scratch
                .admit(&request, &view, &fee, &escrow_domain)
                .with_context(|| format!("admission {i} is within the 12e18 deposit"))?;
        }
        let thirteenth = ProofRequestV2::sign(
            base_request(13),
            cid,
            allocator.next_round_robin()?,
            &spend_key,
            &escrow_domain,
        )?;
        let err = scratch
            .admit(&thirteenth, &view, &fee, &escrow_domain)
            .expect_err("13 units cost 13e18 against a 12e18 deposit");
        assert!(
            matches!(err, AdmitError::Insolvent { .. }),
            "expected insolvency, got {err}"
        );
        drop(scratch);

        // ── Settle ──────────────────────────────────────────────────────────────
        let batch = ledger.settlement_batch(cid);
        assert_eq!(batch.len(), 2, "one authorisation per lane");
        let auths: Vec<SolPaymentAuthorization> = batch.iter().map(to_sol_auth).collect();

        let escrow_as_collector = WorldIDFeeEscrow::new(escrow_addr, as_collector.clone());
        escrow_as_collector
            .settle(cid, auths.clone())
            .send()
            .await?
            .watch()
            .await?;
        ledger.mark_settled(cid);

        let token_view = ERC20Mock::new(*token.address(), as_deployer.clone());
        assert_eq!(
            token_view.balanceOf(collector.address()).call().await?,
            U256::from(10u64) * price(),
            "collector paid for ten verifications"
        );
        let settled = escrow_as_payer.getChannel(cid).call().await?;
        assert_eq!(settled.settledCount, U256::from(10u64));
        assert_eq!(escrow_as_payer.laneHighWater(cid, 0).call().await?, 5);
        assert_eq!(escrow_as_payer.laneHighWater(cid, 1).call().await?, 5);

        // ── Replay ──────────────────────────────────────────────────────────────
        let replay = escrow_as_collector
            .settle(cid, auths)
            .call()
            .await
            .expect_err("re-submitting the same batch must revert");
        let decoded = replay
            .as_decoded_interface_error::<WorldIDFeeEscrow::WorldIDFeeEscrowErrors>()
            .expect("revert must decode against the escrow ABI");
        assert!(
            matches!(
                decoded,
                WorldIDFeeEscrow::WorldIDFeeEscrowErrors::StaleNonce(_)
            ),
            "expected StaleNonce, got {decoded:?}"
        );

        // ── Close after the collection deadline ─────────────────────────────────
        as_deployer.anvil_increase_time(3601).await?;
        as_deployer.anvil_mine(Some(1), None).await?;

        let payer_before = token_view.balanceOf(payer.address()).call().await?;
        WorldIDFeeEscrow::new(escrow_addr, as_payer.clone())
            .closeChannel(cid)
            .send()
            .await?
            .watch()
            .await?;
        let payer_after = token_view.balanceOf(payer.address()).call().await?;
        assert_eq!(
            payer_after - payer_before,
            U256::from(2u64) * price(),
            "unspent deposit is refunded"
        );

        Ok(())
    }

    /// Converts the crate's typed-data settings into the contract binding's struct.
    const fn to_sol_settings(settings: &ChannelSettings) -> SolChannelSettings {
        SolChannelSettings {
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

    fn to_sol_auth(
        auth: &world_id_fee_escrow::OnchainPaymentAuthorization,
    ) -> SolPaymentAuthorization {
        SolPaymentAuthorization {
            channelNonce: alloy::primitives::Uint::<96, 2>::from(auth.channel_nonce),
            rpRequestDigest: auth.rp_request_digest,
            signature: auth.signature.clone(),
        }
    }

    /// Reads on-chain channel state into the collector's view.
    async fn read_view<P: Provider + Clone>(
        escrow: &WorldIDFeeEscrow::WorldIDFeeEscrowInstance<P>,
        cid: B256,
        settings: &ChannelSettings,
    ) -> Result<ChannelView> {
        let channel = escrow.getChannel(cid).call().await?;
        Ok(ChannelView {
            channel_id: cid,
            settings: settings.clone(),
            balance: channel.balance,
            paid: channel.paid,
            settled_count: channel.settledCount,
        })
    }
}
