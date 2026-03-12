//! E2E tests for the permissioned gateway relay path.
//!
//! Uses real WorldIDSource, WorldIDSatellite, PermissionedGatewayAdapter,
//! WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry
//! contracts on a local anvil instance.

use std::sync::Arc;

use alloy::primitives::U256;
use alloy_primitives::B256;
use eyre::Result;
use world_id_relay::{
    cli::{AdapterType, SatelliteConfig},
    satellite::PermissionedSatellite,
    Satellite,
};
use world_id_test_utils::anvil::{
    CoreContracts, TestAnvil, WC_CHAIN_ID, permissioned_gateway, world_id_satellite,
};

use crate::helpers;

// ── Permissioned gateway deployment ────────────────────────────────────────

async fn deploy_permissioned_gateway(
    anvil: &TestAnvil,
    core: &CoreContracts,
) -> Result<alloy::primitives::Address> {
    let deployer = anvil.signer(0)?;
    let provider = anvil.wallet_provider(&deployer)?;

    let gateway = permissioned_gateway::PermissionedGatewayAdapter::deploy(
        &provider,
        core.deployer,
        core.satellite_proxy,
        core.source_proxy,
        U256::from(WC_CHAIN_ID),
    )
    .await?;
    let gateway_addr = *gateway.address();

    anvil.authorize_gateway(core.satellite_proxy, gateway_addr).await?;

    Ok(gateway_addr)
}

fn make_satellite(
    anvil: &TestAnvil,
    core: &CoreContracts,
    gateway: alloy::primitives::Address,
) -> Result<PermissionedSatellite> {
    let deployer = anvil.signer(0)?;
    let provider = anvil.wallet_provider(&deployer)?;
    let config = SatelliteConfig {
        name: "test-permissioned".into(),
        adapter: AdapterType::PermissionedWorldchain,
        destination_chain_id: 31337,
        source_address: core.source_proxy,
        gateway,
        satellite: core.satellite_proxy,
        dispute_game_factory: None,
        game_type: 0,
        require_finalized: false,
    };
    Ok(PermissionedSatellite::new(
        "test-permissioned",
        WC_CHAIN_ID,
        &config,
        Arc::new(provider),
    ))
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Full pipeline: createAccount → registerIssuer → propagateState → relay → verify.
#[tokio::test]
async fn e2e_permissioned_full_pipeline() -> Result<()> {
    let anvil = TestAnvil::spawn()?;
    let core = anvil.deploy_state_bridge().await?;
    let gateway = deploy_permissioned_gateway(&anvil, &core).await?;
    let satellite = make_satellite(&anvil, &core, gateway)?;

    // Seed registries with real contract interactions
    let root = anvil.create_bridge_root(&core).await?;
    let issuer = anvil.register_bridge_issuer(&core, 1).await?;

    // Propagate (no OPRF keys — DKG not performed in test)
    let raw = anvil
        .propagate_and_get_commitment(core.source_proxy, vec![1u64], vec![])
        .await?;

    assert_ne!(raw.chain_head, B256::ZERO);

    let commitment = helpers::into_chain_commitment(raw);
    let tx_hash = satellite.relay(&commitment).await?;
    assert_ne!(tx_hash, B256::ZERO);

    // Verify satellite state (read-only provider is fine here)
    let read_provider = anvil.provider()?;
    let sat = world_id_satellite::WorldIDSatelliteInstance::new(core.satellite_proxy, &read_provider);

    assert_eq!(sat.LATEST_ROOT().call().await?, root);

    let chain = sat.KECCAK_CHAIN().call().await?;
    assert_eq!(chain.head, commitment.chain_head);
    assert_eq!(chain.length, 2); // root + issuer (no oprf)

    let sat_issuer = sat.issuerSchemaIdToPubkeyAndProofId(1u64).call().await?;
    assert_eq!(sat_issuer.pubKey.x, issuer.x);
    assert_eq!(sat_issuer.pubKey.y, issuer.y);

    assert!(sat.isValidRoot(root).call().await?);
    assert!(!sat.isValidRoot(U256::from(9999u64)).call().await?);

    Ok(())
}

/// Two sequential propagation rounds — chain extends, both roots valid, keys update.
#[tokio::test]
async fn e2e_permissioned_sequential_rounds() -> Result<()> {
    let anvil = TestAnvil::spawn()?;
    let core = anvil.deploy_state_bridge().await?;
    let gateway = deploy_permissioned_gateway(&anvil, &core).await?;
    let satellite_impl = make_satellite(&anvil, &core, gateway)?;

    let read_provider = anvil.provider()?;
    let sat = world_id_satellite::WorldIDSatelliteInstance::new(core.satellite_proxy, &read_provider);

    // ── Round 1 ──
    let root1 = anvil.create_bridge_root(&core).await?;
    let issuer1 = anvil.register_bridge_issuer(&core, 1).await?;

    let c1 = helpers::into_chain_commitment(
        anvil
            .propagate_and_get_commitment(core.source_proxy, vec![1u64], vec![])
            .await?,
    );
    satellite_impl.relay(&c1).await?;

    assert_eq!(sat.LATEST_ROOT().call().await?, root1);
    assert_eq!(sat.KECCAK_CHAIN().call().await?.head, c1.chain_head);

    // ── Round 2: new account (updates root) ──
    let root2 = anvil.create_bridge_root(&core).await?;
    assert_ne!(root1, root2);

    let c2 = helpers::into_chain_commitment(
        anvil
            .propagate_and_get_commitment(core.source_proxy, vec![1u64], vec![])
            .await?,
    );
    assert_ne!(c1.chain_head, c2.chain_head);

    // Recreate satellite with a fresh provider to avoid stale nonce cache.
    let satellite_impl = make_satellite(&anvil, &core, gateway)?;
    satellite_impl.relay(&c2).await?;

    assert_eq!(sat.LATEST_ROOT().call().await?, root2);
    assert_eq!(sat.KECCAK_CHAIN().call().await?.head, c2.chain_head);

    // Both roots valid within window
    assert!(sat.isValidRoot(root1).call().await?);
    assert!(sat.isValidRoot(root2).call().await?);

    // Issuer key unchanged (same schema ID, same key)
    let sat_issuer = sat.issuerSchemaIdToPubkeyAndProofId(1u64).call().await?;
    assert_eq!(sat_issuer.pubKey.x, issuer1.x);
    assert_eq!(sat_issuer.pubKey.y, issuer1.y);

    Ok(())
}
