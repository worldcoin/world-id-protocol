#![cfg(feature = "authenticator")]

use alloy::primitives::U256;
use test_utils::anvil::TestAnvil;
use world_id_core::{Authenticator, AuthenticatorError};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig};
use world_id_primitives::Config;

const GW_PORT: u16 = 4102;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_authenticator_registration() {
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");

    let deployer = anvil.signer(0).unwrap();

    let registry_address = anvil
        .deploy_account_registry(deployer.clone())
        .await
        .expect("failed to deploy account registry");

    // Spawn gateway pointing to the same anvil instance
    let gateway_config = GatewayConfig {
        registry_addr: registry_address,
        rpc_url: anvil.endpoint().to_string(),
        wallet_private_key: Some(hex::encode(deployer.to_bytes())),
        aws_kms_key_id: None,
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
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

    // Account doesn't exist, so init will error
    let result = Authenticator::init(&seed, config.clone()).await;
    assert!(matches!(
        result,
        Err(AuthenticatorError::AccountDoesNotExist)
    ),);

    // Create the account (awaits until creation)
    let start = std::time::Instant::now();
    let authenticator =
        Authenticator::init_or_create_blocking(&seed, config.clone(), Some(recovery_address))
            .await
            .unwrap();
    let elapsed = start.elapsed();
    println!("Account creation successful in {elapsed:?}");
    assert_eq!(authenticator.account_id(), U256::from(1));
    assert_eq!(authenticator.recovery_counter(), U256::from(0));

    // If we initialize again, it will work
    let authenticator = Authenticator::init(&seed, config).await.unwrap();
    assert_eq!(authenticator.account_id(), U256::from(1));
}
