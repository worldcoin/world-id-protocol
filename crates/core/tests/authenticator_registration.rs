#![cfg(feature = "authenticator")]

use alloy::primitives::U256;
use backon::{ExponentialBuilder, Retryable};
use world_id_core::{Authenticator, AuthenticatorError, api_types::GatewayRequestState};
use world_id_gateway::{GatewayConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_primitives::Config;
use world_id_test_utils::anvil::TestAnvil;

const GW_PORT: u16 = 4102;

fn load_embedded_materials() -> (
    world_id_core::proof::CircomGroth16Material,
    world_id_core::proof::CircomGroth16Material,
) {
    let files = world_id_core::proof::load_embedded_circuit_files().unwrap();
    let query_material =
        world_id_core::proof::load_query_material_from_bytes(&files.query_zkey, &files.query_graph)
            .unwrap();
    let nullifier_material = world_id_core::proof::load_nullifier_material_from_bytes(
        &files.nullifier_zkey,
        &files.nullifier_graph,
    )
    .unwrap();
    (query_material, nullifier_material)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_authenticator_registration() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");

    let deployer = anvil.signer(0).unwrap();

    let registry_address = anvil
        .deploy_world_id_registry(deployer.clone())
        .await
        .unwrap();

    // Spawn gateway pointing to the same anvil instance
    let signer_args = SignerArgs::from_wallet(hex::encode(deployer.to_bytes()));
    let gateway_config = GatewayConfig {
        registry_addr: registry_address,
        provider: world_id_gateway::ProviderArgs {
            http: Some(vec![anvil.endpoint().parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: None,
        rate_limit_max_requests: None,
        rate_limit_window_secs: None,
    };
    let _gateway = spawn_gateway_for_tests(gateway_config)
        .await
        .expect("failed to spawn gateway");

    let config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        registry_address,
        "http://127.0.0.1:0".to_string(), // not needed for this test
        format!("http://127.0.0.1:{GW_PORT}"),
        Vec::new(),
        2,
    )
    .unwrap();

    let seed = [1u8; 32];
    let recovery_address = anvil.signer(1).unwrap().address();
    let (query_material, nullifier_material) = load_embedded_materials();

    // Account doesn't exist, so init will error
    let result =
        Authenticator::init(&seed, config.clone(), query_material, nullifier_material).await;
    assert!(matches!(
        result,
        Err(AuthenticatorError::AccountDoesNotExist)
    ),);

    // Create the account (awaits until creation)
    // NOTE how we use `register()` instead of `init_or_register()` to test this specific flow.
    let start = std::time::Instant::now();
    let initializing_account =
        Authenticator::register(&seed, config.clone(), Some(recovery_address))
            .await
            .unwrap();

    let poller = || async {
        match initializing_account.poll_status().await {
            Ok(GatewayRequestState::Finalized { .. }) => Ok(()),
            _ => Err(""),
        }
    };

    poller
        .retry(ExponentialBuilder::default().with_max_times(10))
        .await
        .unwrap();

    let (query_material, nullifier_material) = load_embedded_materials();
    let authenticator =
        Authenticator::init(&seed, config.clone(), query_material, nullifier_material)
            .await
            .unwrap();
    let elapsed = start.elapsed();
    println!("Account creation successful in {elapsed:?}");
    assert_eq!(authenticator.leaf_index(), 1);
    assert_eq!(authenticator.recovery_counter(), U256::from(0));

    // If we initialize again, it will work
    let (query_material, nullifier_material) = load_embedded_materials();
    let authenticator = Authenticator::init(&seed, config, query_material, nullifier_material)
        .await
        .unwrap();
    assert_eq!(authenticator.leaf_index(), 1);
}
