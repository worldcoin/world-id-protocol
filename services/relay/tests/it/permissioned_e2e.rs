//! E2E tests for the permissioned gateway relay path.
//!
//! Uses real WorldIDSource, WorldIDSatellite, PermissionedGatewayAdapter,
//! WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry
//! contracts on a local anvil instance.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    sol_types::SolCall,
};
use alloy_primitives::B256;
use ark_ff::PrimeField as _;
use eyre::{Context, Result};
use world_id_primitives::Signer;
use world_id_relay::{
    Engine, Satellite, WorldChainConfig,
    cli::{PermissionedGatewayConfig, WorldChain},
    primitives::ChainCommitment,
    satellite::PermissionedSatellite,
};
use world_id_test_utils::anvil::{
    ERC1967Proxy, MockOprfKeyRegistry, TestAnvil, Verifier, WC_CHAIN_ID,
    get_latest_chain_commitment, permissioned_gateway, world_id_satellite, world_id_source,
};

/// Counter to generate unique accounts across test calls.
static ACCOUNT_COUNTER: AtomicU64 = AtomicU64::new(1);

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Deploys the full state bridge stack and returns the key addresses:
/// (source_proxy, satellite_proxy, world_id_registry, credential_registry, oprf_key_registry, deployer).
async fn deploy_state_bridge(
    anvil: &TestAnvil,
) -> Result<(Address, Address, Address, Address, Address, Address)> {
    let deployer = anvil.signer(0)?;

    let world_id_registry = anvil
        .deploy_world_id_registry(deployer.clone())
        .await
        .context("failed to deploy WorldIDRegistry")?;

    let oprf_key_registry = anvil
        .deploy_mock_oprf_key_registry(deployer.clone())
        .await
        .context("failed to deploy MockOprfKeyRegistry")?;

    let credential_registry = anvil
        .deploy_credential_schema_issuer_registry(deployer.clone(), oprf_key_registry)
        .await
        .context("failed to deploy CredentialSchemaIssuerRegistry")?;

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(deployer.clone()))
        .connect_http(anvil.endpoint().parse().unwrap());

    // WorldIDSource impl + proxy
    let source_impl = world_id_source::WorldIDSource::deploy(
        &provider,
        world_id_registry,
        credential_registry,
        oprf_key_registry,
    )
    .await
    .context("failed to deploy WorldIDSource impl")?;

    let src_init_cfg = world_id_source::IStateBridge::InitConfig {
        name: "World ID Source".into(),
        version: "1".into(),
        owner: deployer.address(),
        authorizedGateways: vec![],
    };
    let src_init_data: Bytes =
        SolCall::abi_encode(&world_id_source::initializeCall { cfg: src_init_cfg }).into();

    let source_proxy = *ERC1967Proxy::deploy(&provider, *source_impl.address(), src_init_data)
        .await
        .context("failed to deploy WorldIDSource proxy")?
        .address();

    // Verifier + WorldIDSatellite impl + proxy
    let verifier = Verifier::deploy(&provider)
        .await
        .context("failed to deploy Verifier")?;

    let sat_impl = world_id_satellite::WorldIDSatellite::deploy(
        &provider,
        *verifier.address(),
        U256::from(3600u64),
        U256::from(30u64),
        60u64,
    )
    .await
    .context("failed to deploy WorldIDSatellite impl")?;

    let sat_init_cfg = world_id_satellite::IStateBridge::InitConfig {
        name: "World ID Bridge".into(),
        version: "1".into(),
        owner: deployer.address(),
        authorizedGateways: vec![],
    };
    let sat_init_data: Bytes =
        SolCall::abi_encode(&world_id_satellite::initializeCall { cfg: sat_init_cfg }).into();

    let satellite_proxy = *ERC1967Proxy::deploy(&provider, *sat_impl.address(), sat_init_data)
        .await
        .context("failed to deploy WorldIDSatellite proxy")?
        .address();

    Ok((
        source_proxy,
        satellite_proxy,
        world_id_registry,
        credential_registry,
        oprf_key_registry,
        deployer.address(),
    ))
}

/// Deploys the permissioned gateway and authorizes it on the satellite.
async fn deploy_gateway(
    anvil: &TestAnvil,
    deployer: Address,
    source_proxy: Address,
    satellite_proxy: Address,
) -> Result<Address> {
    let signer = anvil.signer(0)?;
    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(anvil.endpoint().parse().unwrap());

    let gateway = permissioned_gateway::PermissionedGatewayAdapter::deploy(
        &provider,
        deployer,
        satellite_proxy,
        source_proxy,
        U256::from(WC_CHAIN_ID),
    )
    .await?;
    let gateway_addr = *gateway.address();

    // Authorize the gateway on the satellite
    let sat = world_id_satellite::WorldIDSatelliteInstance::new(satellite_proxy, &provider);
    sat.addGateway(gateway_addr)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(gateway_addr)
}

/// Creates a `PermissionedSatellite` with a fresh provider.
fn make_satellite(
    anvil: &TestAnvil,
    satellite_proxy: Address,
    gateway: Address,
) -> Result<PermissionedSatellite> {
    let deployer = anvil.signer(0)?;
    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(deployer))
        .connect_http(anvil.endpoint().parse().unwrap())
        .erased();
    let config = PermissionedGatewayConfig {
        name: "test-permissioned".into(),
        destination_chain_id: 31337,
        gateway,
        satellite: satellite_proxy,
    };
    Ok(PermissionedSatellite::new(
        "test-permissioned",
        WC_CHAIN_ID,
        &config,
        Arc::new(provider),
    ))
}

/// Creates an account in WorldIDRegistry and returns the latest root.
async fn create_root(anvil: &TestAnvil, world_id_registry: Address) -> Result<U256> {
    let deployer = anvil.signer(0)?;
    let n = ACCOUNT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let auth_signer = anvil.signer(n as usize % 9 + 1)?;
    let root = anvil
        .create_account(
            world_id_registry,
            deployer,
            auth_signer.address(),
            U256::from(n),
            U256::from(n),
        )
        .await;
    Ok(U256::from_be_bytes(root.to_be_bytes()))
}

/// Registers an issuer and returns (pubkey_x, pubkey_y).
async fn register_issuer(
    anvil: &TestAnvil,
    credential_registry: Address,
    schema_id: u64,
) -> Result<(U256, U256)> {
    let deployer = anvil.signer(0)?;
    let signer =
        Signer::from_seed_bytes(&[schema_id as u8; 32]).context("failed to create signer")?;
    let pubkey = signer.offchain_signer_pubkey();

    anvil
        .register_issuer(credential_registry, deployer, schema_id, pubkey.clone())
        .await
        .context("failed to register issuer")?;

    Ok((
        U256::from_limbs(pubkey.pk.x.into_bigint().0),
        U256::from_limbs(pubkey.pk.y.into_bigint().0),
    ))
}

/// Propagates state and returns the chain commitment.
async fn propagate(
    anvil: &TestAnvil,
    source_proxy: Address,
    issuer_ids: Vec<u64>,
) -> Result<ChainCommitment> {
    let deployer = anvil.signer(0)?;
    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(deployer))
        .connect_http(anvil.endpoint().parse().unwrap())
        .erased();

    let source = world_id_source::WorldIDSourceInstance::new(source_proxy, &provider);
    source
        .propagateState(issuer_ids, vec![])
        .send()
        .await?
        .get_receipt()
        .await?;

    let raw = get_latest_chain_commitment(&provider, source_proxy).await?;
    Ok(ChainCommitment {
        chain_head: raw.chain_head,
        block_number: raw.block_number,
        chain_id: raw.chain_id,
        commitment_payload: raw.commitment_payload,
        timestamp: raw.timestamp,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Full pipeline: createAccount → registerIssuer → initKeyGen → propagateState → relay → verify.
#[tokio::test]
async fn e2e_permissioned_full_pipeline() -> Result<()> {
    let anvil = TestAnvil::spawn()?;
    let (
        source_proxy,
        satellite_proxy,
        world_id_registry,
        credential_registry,
        oprf_key_registry,
        deployer,
    ) = deploy_state_bridge(&anvil).await?;
    let gateway = deploy_gateway(&anvil, deployer, source_proxy, satellite_proxy).await?;
    let satellite = make_satellite(&anvil, satellite_proxy, gateway)?;

    let root = create_root(&anvil, world_id_registry).await?;
    let (issuer_x, issuer_y) = register_issuer(&anvil, credential_registry, 1).await?;

    // Verify that issuer registration triggered initKeyGen on the mock OPRF registry.
    // CredentialSchemaIssuerRegistry.register() calls initKeyGen(uint160(issuerSchemaId)).
    let read_provider = anvil.provider()?;
    let oprf =
        MockOprfKeyRegistry::MockOprfKeyRegistryInstance::new(oprf_key_registry, &read_provider);
    assert!(
        oprf.registeredKeys(alloy::primitives::Uint::<160, 3>::from(1u64))
            .call()
            .await?
    );

    let commitment = propagate(&anvil, source_proxy, vec![1u64]).await?;
    assert_ne!(commitment.chain_head, B256::ZERO);

    let tx_hash = satellite.relay(&commitment).await?;
    assert_ne!(tx_hash, B256::ZERO);

    // Verify satellite state
    let sat = world_id_satellite::WorldIDSatelliteInstance::new(satellite_proxy, &read_provider);

    assert_eq!(sat.LATEST_ROOT().call().await?, root);

    let chain = sat.KECCAK_CHAIN().call().await?;
    assert_eq!(chain.head, commitment.chain_head);
    assert_eq!(chain.length, 2); // root + issuer (no oprf)

    let sat_issuer = sat.issuerSchemaIdToPubkeyAndProofId(1u64).call().await?;
    assert_eq!(sat_issuer.pubKey.x, issuer_x);
    assert_eq!(sat_issuer.pubKey.y, issuer_y);

    assert!(sat.isValidRoot(root).call().await?);
    assert!(!sat.isValidRoot(U256::from(9999u64)).call().await?);

    Ok(())
}

/// Two sequential propagation rounds — chain extends, both roots valid, keys update.
#[tokio::test]
async fn e2e_permissioned_sequential_rounds() -> Result<()> {
    let anvil = TestAnvil::spawn()?;
    let (
        source_proxy,
        satellite_proxy,
        world_id_registry,
        credential_registry,
        oprf_key_registry,
        deployer,
    ) = deploy_state_bridge(&anvil).await?;
    let gateway = deploy_gateway(&anvil, deployer, source_proxy, satellite_proxy).await?;
    let satellite_impl = make_satellite(&anvil, satellite_proxy, gateway)?;

    let read_provider = anvil.provider()?;
    let sat = world_id_satellite::WorldIDSatelliteInstance::new(satellite_proxy, &read_provider);
    let oprf =
        MockOprfKeyRegistry::MockOprfKeyRegistryInstance::new(oprf_key_registry, &read_provider);

    // ── Round 1 ──
    let root1 = create_root(&anvil, world_id_registry).await?;
    let (issuer1_x, issuer1_y) = register_issuer(&anvil, credential_registry, 1).await?;

    // Verify issuer registration triggered initKeyGen
    assert!(
        oprf.registeredKeys(alloy::primitives::Uint::<160, 3>::from(1u64))
            .call()
            .await?
    );

    let c1 = propagate(&anvil, source_proxy, vec![1u64]).await?;
    satellite_impl.relay(&c1).await?;

    assert_eq!(sat.LATEST_ROOT().call().await?, root1);
    assert_eq!(sat.KECCAK_CHAIN().call().await?.head, c1.chain_head);

    // ── Round 2: new account + second issuer (updates root, new OPRF key) ──
    let root2 = create_root(&anvil, world_id_registry).await?;
    assert_ne!(root1, root2);

    let (issuer2_x, issuer2_y) = register_issuer(&anvil, credential_registry, 2).await?;

    // Verify second issuer also triggered initKeyGen
    assert!(
        oprf.registeredKeys(alloy::primitives::Uint::<160, 3>::from(2u64))
            .call()
            .await?
    );

    let c2 = propagate(&anvil, source_proxy, vec![1u64, 2u64]).await?;
    assert_ne!(c1.chain_head, c2.chain_head);

    // Recreate satellite with a fresh provider to avoid stale nonce cache.
    let satellite_impl = make_satellite(&anvil, satellite_proxy, gateway)?;
    satellite_impl.relay(&c2).await?;

    assert_eq!(sat.LATEST_ROOT().call().await?, root2);
    assert_eq!(sat.KECCAK_CHAIN().call().await?.head, c2.chain_head);

    // Both roots valid within window
    assert!(sat.isValidRoot(root1).call().await?);
    assert!(sat.isValidRoot(root2).call().await?);

    // Both issuers propagated
    let sat_issuer1 = sat.issuerSchemaIdToPubkeyAndProofId(1u64).call().await?;
    assert_eq!(sat_issuer1.pubKey.x, issuer1_x);
    assert_eq!(sat_issuer1.pubKey.y, issuer1_y);

    let sat_issuer2 = sat.issuerSchemaIdToPubkeyAndProofId(2u64).call().await?;
    assert_eq!(sat_issuer2.pubKey.x, issuer2_x);
    assert_eq!(sat_issuer2.pubKey.y, issuer2_y);

    Ok(())
}

/// Runs the relay Engine as a background service and verifies that it
/// automatically detects registry events, calls propagateState, and relays
/// the resulting commitment to the satellite — one operation at a time.
///
/// Round 1: create an account → root changes → engine propagates → satellite updated.
/// Round 2: register an issuer → key changes → engine propagates → satellite updated.
#[tokio::test]
async fn e2e_engine_driven_pipeline() -> Result<()> {
    let anvil = TestAnvil::spawn()?;
    let (
        source_proxy,
        satellite_proxy,
        world_id_registry,
        credential_registry,
        oprf_key_registry,
        deployer,
    ) = deploy_state_bridge(&anvil).await?;
    let gateway = deploy_gateway(&anvil, deployer, source_proxy, satellite_proxy).await?;

    // Share a single wallet-backed provider between the engine and satellite
    // so nonce management is sequential (both send txs via signer(0)).
    let shared_signer = anvil.signer(0)?;
    let shared_provider = Arc::new(
        ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(shared_signer))
            .connect_http(anvil.endpoint().parse().unwrap())
            .erased(),
    );

    let wc_config = WorldChainConfig {
        chain_id: WC_CHAIN_ID,
        world_id_source: source_proxy,
        oprf_key_registry,
        credential_issuer_schema_registry: credential_registry,
        world_id_registry,
        bridge_interval: 1,
    };

    let world_chain = WorldChain::new(&wc_config, shared_provider.clone());
    let mut engine = Engine::new(world_chain);
    let log = engine.log().clone();

    let sat_config = PermissionedGatewayConfig {
        name: "test-permissioned".into(),
        destination_chain_id: 31337,
        gateway,
        satellite: satellite_proxy,
    };
    let satellite = PermissionedSatellite::new(
        "test-permissioned",
        WC_CHAIN_ID,
        &sat_config,
        shared_provider,
    );
    engine.spawn_satellite(satellite);

    let engine_handle = tokio::spawn(async move { engine.run().await });

    // Give the engine a moment to initialize event streams.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let read_provider = anvil.provider()?;
    let sat = world_id_satellite::WorldIDSatelliteInstance::new(satellite_proxy, &read_provider);

    // ── Round 1: create account → root update ───────────────────────────────
    let root = create_root(&anvil, world_id_registry).await?;

    // Wait for the root to be relayed to the satellite.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() > deadline {
            engine_handle.abort();
            eyre::bail!("timed out waiting for root to be relayed");
        }
        if sat.LATEST_ROOT().call().await? == root {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    assert!(sat.isValidRoot(root).call().await?);
    assert!(!sat.isValidRoot(U256::from(9999u64)).call().await?);

    let chain_after_root = sat.KECCAK_CHAIN().call().await?;
    assert_ne!(chain_after_root.head, B256::ZERO);
    assert_eq!(chain_after_root.length, 1); // root only

    // Pending state should be cleared after round 1.
    assert!(
        !log.has_pending_keys(),
        "pending state should be cleared after root propagation"
    );

    // ── Round 2: register issuer → key update ───────────────────────────────
    let (issuer_x, issuer_y) = register_issuer(&anvil, credential_registry, 1).await?;

    // Wait for the issuer to be relayed to the satellite.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() > deadline {
            engine_handle.abort();
            eyre::bail!("timed out waiting for issuer to be relayed");
        }
        let sat_issuer = sat.issuerSchemaIdToPubkeyAndProofId(1u64).call().await?;
        if sat_issuer.pubKey.x == issuer_x {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let sat_issuer = sat.issuerSchemaIdToPubkeyAndProofId(1u64).call().await?;
    assert_eq!(sat_issuer.pubKey.x, issuer_x);
    assert_eq!(sat_issuer.pubKey.y, issuer_y);

    let chain_after_issuer = sat.KECCAK_CHAIN().call().await?;
    assert_ne!(chain_after_issuer.head, chain_after_root.head);
    assert_eq!(chain_after_issuer.length, 2); // root + issuer

    // Root from round 1 should still be valid.
    assert!(sat.isValidRoot(root).call().await?);

    // Pending state should be cleared after round 2.
    assert!(
        !log.has_pending_keys(),
        "pending state should be cleared after issuer propagation"
    );
    let (pending_issuers, pending_oprfs) = log.pending_propagation_ids();
    assert!(pending_issuers.is_empty());
    assert!(pending_oprfs.is_empty());

    // Commitment log head should match the satellite.
    assert_eq!(log.head(), chain_after_issuer.head);

    engine_handle.abort();
    Ok(())
}
